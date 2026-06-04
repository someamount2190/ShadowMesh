package mesh.shadowmesh.app

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.ForumViewModel
import mesh.shadowmesh.forum.KeyOrchestrator
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.mesh.mode.NetworkModeStateMachine
import javax.inject.Named
import javax.inject.Singleton

/**
 * Hilt module — bridges the manual-DI [AppModule] object graph into the Hilt
 * component graph so that [@HiltViewModel] classes can inject SHADOWMESH singletons.
 *
 * ## Why manual DI + Hilt coexist
 *
 * SHADOWMESH's core object graph is built manually in [ShadowMeshApplication] via
 * [AppModule.initialise]. This is intentional: the 12-phase construction order
 * has explicit async steps (Keystore I/O, APK hash) that don't fit Hilt's
 * synchronous provider model. However, UI-layer ViewModels use [@HiltViewModel]
 * for correct configuration-change survival.
 *
 * This module bridges them: each @Provides delegates to the already-constructed
 * [AppModule] singleton after guarding on [AppModule.isInitialised].
 *
 * ## Init guard
 *
 * Providers throw [IllegalStateException] if called before init completes.
 * In practice [MainActivity.observeApplicationState] polls for init before
 * setting content, so ViewModels are not created prematurely.
 */
@Module
@InstallIn(SingletonComponent::class)
object ShadowMeshHiltModule {

    private fun requireInit(name: String): Nothing =
        error("Hilt requested '$name' before AppModule init. " +
              "Ensure AppModule.isInitialised before navigating to ViewModel screens.")

    @Provides @Singleton
    fun provideChannelManager(): ChannelManager =
        if (AppModule.isInitialised) AppModule.channelManager else requireInit("ChannelManager")

    @Provides @Singleton
    fun providePostEngine(): PostEngine =
        if (AppModule.isInitialised) AppModule.postEngine else requireInit("PostEngine")

    @Provides @Singleton
    fun provideNetworkModeStateMachine(): NetworkModeStateMachine =
        if (AppModule.isInitialised) AppModule.networkModeSM else requireInit("NetworkModeStateMachine")

    /**
     * Provides the [ForumViewModel] domain-layer instance.
     *
     * [ForumViewModel] is constructed in [ShadowMeshApplication.buildObjectGraph] (Phase 7)
     * and stored in [AppModule.forumViewModel]. Its lifecycle is application-scoped
     * (not Android ViewModel lifecycle) — it is distinct from [ForumUiViewModel] which
     * IS a proper Android ViewModel and wraps this for the UI.
     *
     * The fragment dispatcher is wired to [AppModule.postDispatcher.dispatch] so
     * that ForumViewModel retry calls flow through the full outbound pipeline.
     */
    @Provides @Singleton
    fun provideForumViewModel(): ForumViewModel =
        if (AppModule.isInitialised) AppModule.forumViewModel else requireInit("ForumViewModel")

    @Provides @Singleton
    fun provideKeyOrchestrator(): KeyOrchestrator =
        if (AppModule.isInitialised) AppModule.keyOrchestrator else requireInit("KeyOrchestrator")

    /**
     * Provides the [AttestedPhysicalExchange] singleton for [OnboardingViewModel].
     * Used to construct [NfcBootstrapCoordinator] per-bootstrap-session.
     */
    @Provides @Singleton
    fun provideAttestedExchange(): mesh.shadowmesh.attestation.AttestedPhysicalExchange =
        if (AppModule.isInitialised) AppModule.attestedExchange else requireInit("AttestedExchange")

    /**
     * Whether the onboarding flow must require hardware attestation from the peer.
     * True only in deployments where attestation roots are fully configured
     * (README Open Item #1 resolved). False in the open-source build.
     *
     * The [@Named] qualifier disambiguates this Boolean binding from any other
     * Boolean providers Hilt might encounter in the component graph.
     * [OnboardingViewModel] injects it via [@Named("attestationRequired")].
     */
    @Provides
    @Named("attestationRequired")
    fun provideAttestationRequired(): Boolean = AppModule.attestationRequired

    @Provides @Singleton
    fun provideGossipEngine(): GossipEngine =
        if (AppModule.isInitialised) AppModule.gossipEngine else requireInit("GossipEngine")

    @Provides
    @Named("localNodeId")
    fun provideLocalNodeId(): String =
        if (AppModule.isInitialised) AppModule.localIdentity.nodeId.toHex() else ""

    /**
     * Provides the raw device secret ByteArray for PIN key derivation in OnboardingViewModel.
     * The reference is the same object AppModule holds — fill(0) during a panic wipe zeroes
     * this injected array as well, which is the correct behaviour.
     */
    @Provides
    @Named("deviceSecret")
    fun provideDeviceSecret(): ByteArray =
        if (AppModule.isInitialised) AppModule.deviceSecret
        else ByteArray(32)  // safe fallback — OnboardingViewModel is only created post-init

    @Provides @Singleton
    fun provideDuressPinManager(): mesh.shadowmesh.security.DuressPinManager =
        if (AppModule.isInitialised) AppModule.duressPinMgr else requireInit("DuressPinManager")

    @Provides @Singleton
    fun provideVpnBridge(): mesh.shadowmesh.platform.VpnServiceBridge =
        if (AppModule.isInitialised) AppModule.vpnBridge else requireInit("VpnBridge")

    /**
     * Provides the [NfcBootstrapCoordinator] for [OnboardingViewModel].
     * Returns null when [AppModule] is not yet initialised (pre-init nav guard
     * in [MainActivity.observeApplicationState] prevents ViewModel creation before init).
     * The coordinator is application-scoped as a singleton; [OnboardingViewModel.retryBootstrap]
     * calls coordinator.reset() between sessions.
     */
    @Provides @Singleton
    fun provideNfcBootstrapCoordinator(
        @dagger.hilt.android.qualifiers.ApplicationContext context: android.content.Context
    ): mesh.shadowmesh.attestation.nfc.NfcBootstrapCoordinator? {
        if (!AppModule.isInitialised) return null
        return mesh.shadowmesh.attestation.nfc.NfcBootstrapCoordinator(
            localIdentity      = AppModule.localIdentity.publicPart,
            localPrivateKey    = AppModule.localIdentity.privatePart.signingPrivateKey,
            baseExchange       = AppModule.physicalKeyExchange,
            nfcHandshake       = AppModule.nfcHandshake,
            scope              = AppModule.applicationScope,
            attestedExchange   = AppModule.attestedExchange,
            context            = context,
            requireAttestation = AppModule.attestationRequired
        )
    }
}
