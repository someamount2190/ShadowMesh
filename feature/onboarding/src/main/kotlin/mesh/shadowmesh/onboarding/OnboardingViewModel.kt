// TODO: [BLE Redesign] BleProximityScanner lifecycle added. proximityConfirmed StateFlow added.
// ASSUMPTION: Initiator scanner uses targetNodeIdBytes=null (peer node ID not yet known).
// ASSUMPTION: Responder scanner uses qr.nodeId (initiator's node ID from scanned QR code).
// ASSUMPTION: viewModelScope is the scanner's CoroutineScope; scanner is stopped on
// onCleared() ensuring no resource leak if the user navigates away mid-bootstrap.

package mesh.shadowmesh.onboarding
import mesh.shadowmesh.diagnostics.Diag

import android.content.Context
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import mesh.shadowmesh.attestation.AttestationTrustLevel
import mesh.shadowmesh.attestation.nfc.BootstrapResult
import mesh.shadowmesh.attestation.nfc.BootstrapState
import mesh.shadowmesh.bootstrap.nfc.BootstrapTrustLevel
import mesh.shadowmesh.attestation.nfc.NfcBootstrapCoordinator
import mesh.shadowmesh.bootstrap.QrIntroductionCode
import mesh.shadowmesh.bootstrap.ble.BleProximityScanner
import mesh.shadowmesh.platform.BiometricEnrollmentChecker
import mesh.shadowmesh.platform.OemBatteryExemption
import mesh.shadowmesh.platform.VpnServiceBridge
import mesh.shadowmesh.security.DuressPinManager
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Named

/**
 * Onboarding wizard ViewModel — Phase 9.
 *
 * Drives an 8-step onboarding flow that ensures the device is correctly
 * configured before the user can send or receive messages.
 *
 * Steps (in order):
 *   1. WELCOME            — App introduction + threat model summary
 *   2. BIOMETRIC_CHECK    — Verify enrollment; prompt to enroll if needed
 *   3. BATTERY_EXEMPTION  — Request Doze exemption + OEM-specific deep bg
 *   4. VPN_PERMISSION     — One-time VpnService consent for the circuit tunnel (persists)
 *   5. DURESS_PIN_SETUP   — Set up real PIN + duress PIN (optional but urged)
 *   6. ENTRY_NODE_SETUP   — Explain Entry Node trust model; pick first Entry Node
 *   7. PHYSICAL_EXCHANGE  — Prompt to physically exchange keys with ≥1 trusted contact
 *   8. COMPLETE           — Summary of configured protections + first-launch checklist
 *
 * Skip policy:
 *   - Steps 4 (VPN), 5 (duress PIN) and 6 (entry node) can be skipped (deferred to Settings).
 *   - Steps 2 (biometric) and 3 (battery) cannot be skipped — they are prerequisites
 *     for correct operation.
 *   - Step 7 (physical exchange) can be skipped but shows a warning.
 *
 * Thread-safety: all state updates on viewModelScope (Main dispatcher).
 */
@HiltViewModel
class OnboardingViewModel @Inject constructor(
    @ApplicationContext private val context:              Context,
    private val duressPinManager:     DuressPinManager,
    private val vpnBridge:            VpnServiceBridge,
    /**
     * NfcBootstrapCoordinator wired with AttestedPhysicalExchange. Created fresh
     * per onboarding session by the factory. Null in tests that don't exercise the
     * physical exchange step.
     */
    private val bootstrapCoordinator: NfcBootstrapCoordinator? = null,
    /**
     * When true, the PHYSICAL_EXCHANGE step requires the peer to pass hardware attestation
     * ([BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED]) before [advance] is called.
     * When false, any successful NFC handshake ([TRUST_PHYSICAL_NFC] or better) proceeds.
     *
     * Injected via [ShadowMeshHiltModule.provideAttestationRequired] which derives the
     * value from [mesh.shadowmesh.attestation.HardwareAttestation.isRootConfigured].
     * True only when both Google and GrapheneOS attestation roots are configured (i.e.
     * not placeholder values). With placeholder roots, attestation always fails and
     * setting this true would block all bootstraps.
     */
    @Named("attestationRequired")
    private val attestationRequired:  Boolean = false,
    @Named("deviceSecret")
    private val deviceSecret:         ByteArray = ByteArray(32),
) : ViewModel() {

    // ── BLE proximity scanner state ────────────────────────────────────────

    /**
     * True once [BleProximityScanner] emits [BleProximityScanner.ProximityState.Confirmed]
     * for this session. Observed by [AddContactSheet] to drive the three-stage UI
     * (Scanning → Found → Verified). Resets to false when [retryBootstrap] is called.
     */
    private val _proximityConfirmed = MutableStateFlow(false)
    val proximityConfirmed: StateFlow<Boolean> = _proximityConfirmed.asStateFlow()

    @Volatile private var activeScanner: BleProximityScanner? = null

    private fun startProximityScanner(targetNodeIdBytes: ByteArray?) {
        stopProximityScanner()
        val scanner = BleProximityScanner(
            context            = context,
            scope              = viewModelScope,
            targetNodeIdBytes  = targetNodeIdBytes
        )
        activeScanner = scanner
        scanner.start()
        viewModelScope.launch {
            scanner.state.collect { state ->
                when (state) {
                    is BleProximityScanner.ProximityState.Confirmed -> {
                        _proximityConfirmed.value = true
                        bootstrapCoordinator?.confirmProximity()
                        stopProximityScanner()
                    }
                    is BleProximityScanner.ProximityState.Timeout -> {
                        stopProximityScanner()
                    }
                    else -> Unit
                }
            }
        }
    }

    private fun stopProximityScanner() {
        activeScanner?.stop()
        activeScanner = null
    }

    override fun onCleared() {
        super.onCleared()
        stopProximityScanner()
    }

    // ── Physical exchange (TRUST_PHYSICAL) step state ─────────────────────

    /**
     * Live state of the NFC bootstrap, mirrored from [NfcBootstrapCoordinator.state].
     * The UI observes this to update the QR code display, NFC status indicator,
     * and trust level badge as the handshake progresses.
     */
    val bootstrapState: StateFlow<BootstrapState> =
        bootstrapCoordinator?.state
            ?: MutableStateFlow(BootstrapState.Idle)

    /**
     * The QR introduction code to display. Set when [startPhysicalExchangeAsInitiator]
     * completes — the UI renders this as a QR image for the peer to scan.
     */
    private val _qrCode = MutableStateFlow<QrIntroductionCode?>(null)
    val qrCode: StateFlow<QrIntroductionCode?> = _qrCode.asStateFlow()

    /**
     * Trust level attained by the completed bootstrap. Null until the handshake
     * succeeds. Displayed in the completion summary and the COMPLETE step badge.
     */
    private val _achievedTrustLevel = MutableStateFlow<BootstrapTrustLevel?>(null)
    val achievedTrustLevel: StateFlow<BootstrapTrustLevel?> = _achievedTrustLevel.asStateFlow()

    /**
     * Attestation level from hardware attestation, or null if attestation was not
     * performed or not available on the peer's device.
     */
    private val _achievedAttestationLevel = MutableStateFlow<AttestationTrustLevel?>(null)
    val achievedAttestationLevel: StateFlow<AttestationTrustLevel?> = _achievedAttestationLevel.asStateFlow()

    /**
     * True when the physical exchange step may proceed past NFC verification.
     *
     * When [attestationRequired] is false (the default), this is always true — any
     * successful NFC handshake is sufficient. When [attestationRequired] is true, the
     * peer must have achieved [BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED]; the UI
     * shows a blocking warning until the user retries with an attested device or
     * explicitly overrides (operator decision).
     *
     * Derived from [_achievedTrustLevel] so it updates reactively when the handshake
     * result arrives without requiring the UI to compute it locally.
     */
    val attestationGatePassed: StateFlow<Boolean> = _achievedTrustLevel
        .map { level ->
            !attestationRequired ||
            level == BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED
        }
        .stateIn(viewModelScope, SharingStarted.Eagerly, !attestationRequired)

    /**
     * Error message from the bootstrap if it failed. Shown as a banner in the UI.
     * Cleared on retry.
     */
    private val _bootstrapError = MutableStateFlow<String?>(null)
    val bootstrapError: StateFlow<String?> = _bootstrapError.asStateFlow()

    /**
     * Start as initiator: generate the QR code and wait for NFC tap.
     * Called when the UI enters the PHYSICAL_EXCHANGE step (auto-starts as initiator).
     *
     * On completion, observes [bootstrapState] until [BootstrapState.NfcVerified]
     * or [BootstrapState.Failed], then marks the step complete or surfaces the error.
     */
    fun startPhysicalExchangeAsInitiator() {
        val coordinator = bootstrapCoordinator ?: return
        _bootstrapError.value = null
        _proximityConfirmed.value = false
        // Initiator: peer node ID not yet known — scan for any nearby ShadowMesh device.
        startProximityScanner(targetNodeIdBytes = null)
        viewModelScope.launch {
            try {
                val qr = coordinator.startAsInitiator()
                _qrCode.value = qr
                // Observe state until terminal
                coordinator.state
                    .filter { it is BootstrapState.NfcVerified || it is BootstrapState.Failed }
                    .first()
                    .let { state ->
                        when (state) {
                            is BootstrapState.NfcVerified -> {
                                // Retrieve full result for attestation level
                                val result = coordinator.awaitResult()
                                if (result is BootstrapResult.Success) {
                                    _achievedTrustLevel.value       = result.trustLevel
                                    _achievedAttestationLevel.value = result.peerAttestationLevel
                                }
                                // Gate progression on attestation when required.
                                // attestationGatePassed is derived from _achievedTrustLevel above,
                                // so it is up-to-date by the time we read it here.
                                if (attestationGatePassed.value) {
                                    markStepComplete(OnboardingStep.PHYSICAL_EXCHANGE)
                                    advance()
                                } else {
                                    // Peer lacked hardware attestation — surface the error so
                                    // the user sees it and can retry with an attested device.
                                    _bootstrapError.value =
                                        "Hardware attestation required but peer device did not " +
                                        "provide a verified TEE attestation chain. " +
                                        "Retry with a device running unmodified Android on " +
                                        "genuine hardware, or contact your deployment administrator."
                                    Diag.degraded("onboarding", "attestation-gate-blocked",
                                        "requireAttestation=true but peer achieved ${_achievedTrustLevel.value}; " +
                                        "PHYSICAL_EXCHANGE step blocked.")
                                }
                            }
                            is BootstrapState.Failed ->
                                _bootstrapError.value = state.reason
                            else -> Unit
                        }
                    }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                _bootstrapError.value = e.message ?: "Bootstrap error"
            }
        }
    }

    /**
     * Switch to responder role: scan a peer's QR code bytes and start waiting for NFC.
     * Called when the user taps "Scan instead" in the UI and completes QR scanning.
     *
     * @param qrBytes  Raw bytes decoded from the peer's QR code.
     */
    fun startPhysicalExchangeAsResponder(qrBytes: ByteArray) {
        val coordinator = bootstrapCoordinator ?: return
        _bootstrapError.value = null
        _proximityConfirmed.value = false
        val qrCode = mesh.shadowmesh.bootstrap.QrIntroductionCode.fromBytes(qrBytes)
        // Responder: target the initiator's node ID so only the right peer triggers Confirmed.
        startProximityScanner(targetNodeIdBytes = qrCode.nodeId)
        viewModelScope.launch {
            try {
                coordinator.startAsResponder(qrCode)
                coordinator.state
                    .filter { it is BootstrapState.NfcVerified || it is BootstrapState.Failed }
                    .first()
                    .let { state ->
                        when (state) {
                            is BootstrapState.NfcVerified -> {
                                val result = coordinator.awaitResult()
                                if (result is BootstrapResult.Success) {
                                    _achievedTrustLevel.value       = result.trustLevel
                                    _achievedAttestationLevel.value = result.peerAttestationLevel
                                }
                                if (attestationGatePassed.value) {
                                    markStepComplete(OnboardingStep.PHYSICAL_EXCHANGE)
                                    advance()
                                } else {
                                    _bootstrapError.value =
                                        "Hardware attestation required but peer device did not " +
                                        "provide a verified TEE attestation chain. " +
                                        "Retry with a device running unmodified Android on " +
                                        "genuine hardware, or contact your deployment administrator."
                                    Diag.degraded("onboarding", "attestation-gate-blocked",
                                        "requireAttestation=true but peer achieved ${_achievedTrustLevel.value}; " +
                                        "PHYSICAL_EXCHANGE step blocked.")
                                }
                            }
                            is BootstrapState.Failed ->
                                _bootstrapError.value = state.reason
                            else -> Unit
                        }
                    }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                _bootstrapError.value = e.message ?: "Bootstrap error"
            }
        }
    }

    /** Forward raw NFC APDU bytes from ShadowMeshHceService to the coordinator. */
    suspend fun onNfcApduReceived(apduPayload: ByteArray): ByteArray =
        bootstrapCoordinator?.onHceApduReceived(apduPayload) ?: ByteArray(0)

    /** Exposes the active coordinator so the host (MainActivity via NavGraph) can register it with ShadowMeshHceService. */
    fun activeCoordinator(): NfcBootstrapCoordinator? = bootstrapCoordinator

    /** Reset the bootstrap state machine (e.g., after a failed attempt). */
    fun retryBootstrap() {
        stopProximityScanner()
        _proximityConfirmed.value = false
        // reset() is suspend (acquires stateMutex) — launch on viewModelScope so the
        // main thread is never blocked if the NFC service thread holds the mutex.
        viewModelScope.launch {
            bootstrapCoordinator?.reset()
        }
        _qrCode.value          = null
        _bootstrapError.value  = null
        startPhysicalExchangeAsInitiator()
    }

    // ── Step model ────────────────────────────────────────────────────────

    enum class OnboardingStep {
        WELCOME,
        BIOMETRIC_CHECK,
        BATTERY_EXEMPTION,
        VPN_PERMISSION,
        DURESS_PIN_SETUP,
        ENTRY_NODE_SETUP,
        PHYSICAL_EXCHANGE,
        COMPLETE
    }

    // PHYSICAL_EXCHANGE is intentionally excluded — physical contact exchange is
    // accessible post-onboarding from the Contacts tab (Add Contact → Show QR / Scan).
    private val stepOrder = listOf(
        OnboardingStep.WELCOME,
        OnboardingStep.BIOMETRIC_CHECK,
        OnboardingStep.BATTERY_EXEMPTION,
        OnboardingStep.VPN_PERMISSION,
        OnboardingStep.DURESS_PIN_SETUP,
        OnboardingStep.ENTRY_NODE_SETUP,
        OnboardingStep.COMPLETE,
    )

    private val _currentStep = MutableStateFlow(OnboardingStep.WELCOME)
    val currentStep: StateFlow<OnboardingStep> = _currentStep.asStateFlow()

    private val _completedSteps = MutableStateFlow(setOf<OnboardingStep>())
    val completedSteps: StateFlow<Set<OnboardingStep>> = _completedSteps.asStateFlow()

    // ── Biometric step state ──────────────────────────────────────────────

    private val _biometricStatus = MutableStateFlow(
        BiometricEnrollmentChecker.checkEnrollmentStatus(context)
    )
    val biometricStatus = _biometricStatus.asStateFlow()

    val biometricMessage: StateFlow<String> = _biometricStatus.map {
        BiometricEnrollmentChecker.userMessage(it)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, "")

    // Maps directly from the emitted EnrollmentStatus — does NOT re-query the
    // device. Calling canProceedWithKeyOps(context) inside the map would issue a
    // fresh BiometricManager query independent of _biometricStatus, allowing the
    // two to diverge (e.g., in tests where _biometricStatus is set externally).
    val canProceedPastBiometric: StateFlow<Boolean> = _biometricStatus.map { status ->
        when (status) {
            BiometricEnrollmentChecker.EnrollmentStatus.STRONG_BIOMETRIC_READY,
            BiometricEnrollmentChecker.EnrollmentStatus.WEAK_BIOMETRIC_ONLY,
            BiometricEnrollmentChecker.EnrollmentStatus.CREDENTIAL_ONLY -> true
            else -> false
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    fun refreshBiometricStatus() {
        _biometricStatus.value = BiometricEnrollmentChecker.checkEnrollmentStatus(context)
    }

    fun openBiometricEnrollment() {
        BiometricEnrollmentChecker.openEnrollmentSettings(context)
    }

    // ── Battery exemption step state ──────────────────────────────────────

    val oemRom = OemBatteryExemption.detectOemRom()
    val hasOemExemptionScreen = OemBatteryExemption.hasOemExemptionScreen(context)
    // Use the overload that accepts a pre-detected OemRom — avoids calling detectOemRom() twice
    val oemInstruction = OemBatteryExemption.oemExemptionInstruction(oemRom)

    private val _dozeExempted = MutableStateFlow(OemBatteryExemption.isDozeExempted(context))
    val dozeExempted: StateFlow<Boolean> = _dozeExempted.asStateFlow()

    fun refreshDozeStatus() {
        _dozeExempted.value = OemBatteryExemption.isDozeExempted(context)
    }

    fun requestDozeExemption() {
        OemBatteryExemption.requestDozeExemption(context)
    }

    fun openOemExemptionSettings() {
        OemBatteryExemption.openOemExemptionSettings(context)
    }

    // ── VPN permission step state ─────────────────────────────────────────
    //
    // Phase 8/9: one-time VpnService consent that persists across restart. The onion
    // circuit tunnels device traffic through the mesh; consent is requested once and
    // remembered via VpnServiceBridge. This step is skippable — messaging works without
    // the VPN tunnel; the tunnel can be enabled later from Settings.

    private val _vpnPermissionState = MutableStateFlow(vpnBridge.permissionState())
    val vpnPermissionState: StateFlow<VpnServiceBridge.PermissionState> =
        _vpnPermissionState.asStateFlow()

    /** True while the user still needs to grant (or re-grant) VPN consent. */
    val vpnNeedsConsent: StateFlow<Boolean> = _vpnPermissionState.map {
        it != VpnServiceBridge.PermissionState.GRANTED
    }.stateIn(viewModelScope, SharingStarted.Eagerly, vpnBridge.needsConsent())

    /**
     * Build the system consent Intent, or null if the app is already an authorized VPN.
     * When null is returned, consent is already granted — mark the step complete directly.
     * Otherwise the UI launches the Intent and reports the outcome to [onVpnConsentResult].
     */
    fun prepareVpnConsent(): Intent? {
        val intent = vpnBridge.prepareConsent(context)
        if (intent == null) {
            _vpnPermissionState.value = vpnBridge.permissionState()
            markStepComplete(OnboardingStep.VPN_PERMISSION)
        }
        return intent
    }

    /** Feed back the result of the consent activity (true = RESULT_OK). */
    fun onVpnConsentResult(granted: Boolean) {
        vpnBridge.onConsentResult(granted)
        _vpnPermissionState.value = vpnBridge.permissionState()
        if (granted) {
            vpnBridge.start(context)
            markStepComplete(OnboardingStep.VPN_PERMISSION)
        }
    }

    fun refreshVpnState() {
        _vpnPermissionState.value = vpnBridge.permissionState()
    }

    // ── Duress PIN step state ─────────────────────────────────────────────

    val isPinAlreadyConfigured: Boolean
        get() = duressPinManager.isPinConfigured()

    private val _pinSetupResult = MutableSharedFlow<PinSetupResult>(extraBufferCapacity = 1)
    val pinSetupResult: SharedFlow<PinSetupResult> = _pinSetupResult.asSharedFlow()

    fun setupPins(realPin: ByteArray, duressPin: ByteArray) {
        viewModelScope.launch {
            try {
                duressPinManager.setupPins(realPin, duressPin, deviceSecret)
                _pinSetupResult.emit(PinSetupResult.Success)
                advance()
            } catch (e: IllegalArgumentException) {
                _pinSetupResult.emit(PinSetupResult.Error(e.message ?: "Invalid PIN"))
            } finally {
                // Wipe the caller-owned PIN arrays — the ViewModel received these from the UI
                // and is responsible for zeroing them after use.
                realPin.fill(0)
                duressPin.fill(0)
                // DO NOT wipe deviceSecret here.
                //
                // Bug fixed: the previous code called deviceSecret.fill(0), claiming
                // "OnboardingViewModel holds the last reference". This is INCORRECT —
                // ShadowMeshHiltModule.provideDeviceSecret() injects AppModule.deviceSecret
                // directly (same ByteArray reference). Wiping it here zeroes the global
                // AppModule.deviceSecret for the rest of the session. All subsequent calls to
                // KeyOrchestrator.deriveWrappingKey(), ShadowMeshDatabase key derivation, and
                // IntegrityBoundedKeyDerivation would use an all-zeros device secret, causing:
                //   - New channel key wrapping to produce wrong ciphertext (unrestorable on restart)
                //   - IBD-derived keys to differ from their pre-wipe values (identity mismatch)
                //
                // The ONLY caller permitted to wipe deviceSecret is PanicWipeManager.onWipeComplete,
                // which is the intended consumer of this behaviour. The Hilt module comment
                // confirming the shared reference was correct for that path but was NOT a licence
                // to wipe it during normal PIN setup.
            }
        }
    }

    // ── Navigation ────────────────────────────────────────────────────────

    /**
     * Mark the current step complete and advance to the next.
     * Call when the user actively completes a step (taps "Next" after enrolling,
     * after granting battery exemption, etc.).
     */
    fun advance() {
        val current = _currentStep.value
        markStepComplete(current)
        moveToNext()
    }

    /**
     * Skip the current step WITHOUT marking it complete.
     * A skipped step is distinguishable from a completed step in [completionSummary]
     * — e.g., skipping ENTRY_NODE_SETUP correctly shows "○ Entry Node not configured"
     * rather than "✓ Entry Node configured".
     */
    fun skipStep() {
        val current = _currentStep.value
        require(isSkippable(current)) { "Step $current cannot be skipped" }
        moveToNext()   // does NOT call markStepComplete
    }

    private fun moveToNext() {
        val current   = _currentStep.value
        val nextIndex = stepOrder.indexOf(current) + 1
        if (nextIndex < stepOrder.size) {
            _currentStep.value = stepOrder[nextIndex]
        }
    }

    fun goBack() {
        val current = _currentStep.value
        val prevIndex = stepOrder.indexOf(current) - 1
        if (prevIndex >= 0) {
            _currentStep.value = stepOrder[prevIndex]
        }
    }

    private fun markStepComplete(step: OnboardingStep) {
        _completedSteps.value = _completedSteps.value + step
    }

    fun isStepComplete(step: OnboardingStep): Boolean =
        _completedSteps.value.contains(step)

    fun isSkippable(step: OnboardingStep): Boolean = when (step) {
        OnboardingStep.VPN_PERMISSION,
        OnboardingStep.DURESS_PIN_SETUP,
        OnboardingStep.ENTRY_NODE_SETUP -> true
        else -> false
    }

    /** Reset bootstrap coordinator state without restarting the initiator flow. */
    fun resetBootstrap() {
        viewModelScope.launch {
            bootstrapCoordinator?.reset()
        }
        _qrCode.value         = null
        _bootstrapError.value = null
    }

    // ── Completion state ──────────────────────────────────────────────────

    /**
     * Summary of what was configured during onboarding.
     * Shown on the COMPLETE step.
     */
    val completionSummary: StateFlow<OnboardingCompletionSummary> =
        _completedSteps.map { completed ->
            OnboardingCompletionSummary(
                biometricConfigured  = completed.contains(OnboardingStep.BIOMETRIC_CHECK),
                batteryExempted      = _dozeExempted.value,
                vpnConfigured        = completed.contains(OnboardingStep.VPN_PERMISSION),
                duressPinConfigured  = duressPinManager.isPinConfigured(),
                entryNodeConfigured  = completed.contains(OnboardingStep.ENTRY_NODE_SETUP),
                physicalKeyExchanged = completed.contains(OnboardingStep.PHYSICAL_EXCHANGE)
            )
        }.stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            OnboardingCompletionSummary()
        )
}

// ── Supporting types ──────────────────────────────────────────────────────────

sealed class PinSetupResult {
    object Success                       : PinSetupResult()
    data class Error(val message: String): PinSetupResult()
}

data class OnboardingCompletionSummary(
    val biometricConfigured:  Boolean = false,
    val batteryExempted:      Boolean = false,
    val vpnConfigured:        Boolean = false,
    val duressPinConfigured:  Boolean = false,
    val entryNodeConfigured:  Boolean = false,
    val physicalKeyExchanged: Boolean = false
) {
    val protectionScore: Int get() =
        listOf(biometricConfigured, batteryExempted, vpnConfigured, duressPinConfigured,
               entryNodeConfigured, physicalKeyExchanged).count { it }

    fun summaryLines(): List<String> = buildList {
        add(if (biometricConfigured) "✓ Biometric authentication"     else "⚠ Biometric not confirmed")
        add(if (batteryExempted)     "✓ Battery exemption granted"     else "⚠ Battery exemption not granted")
        add(if (vpnConfigured)       "✓ VPN circuit tunnel authorized" else "○ VPN tunnel not enabled (optional — enable in Settings)")
        add(if (duressPinConfigured) "✓ Duress PIN configured"         else "○ Duress PIN not set (optional)")
        add(if (entryNodeConfigured) "✓ Entry Node configured"         else "○ Entry Node not configured — will use fallback")
        add("○ Add trusted contacts via Contacts → Add Contact after setup")
    }
}
