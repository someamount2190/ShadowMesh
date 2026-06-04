// TODO: [BLE Redesign] proximityConfirmedForSession security gate added.
// ASSUMPTION: confirmProximity() is called by OnboardingViewModel when BleProximityScanner
// emits ProximityState.Confirmed. The coordinator does NOT verify the node ID itself —
// OnboardingViewModel is responsible for calling confirmProximity() only after the
// scanner confirms the expected targetNodeIdBytes match.
// ASSUMPTION: Both NFC entry points (onNfcChallengeReceived + onHceApduReceived) enforce
// the gate. A coordinator created without calling confirmProximity() will refuse all NFC
// handshakes, returning null / SW_NOT_FOUND as appropriate.

package mesh.shadowmesh.attestation.nfc

import mesh.shadowmesh.attestation.AttestedPhysicalExchange
import mesh.shadowmesh.attestation.AttestationEvidence
import mesh.shadowmesh.attestation.AttestationResult
import mesh.shadowmesh.attestation.AttestationTrustLevel
import mesh.shadowmesh.attestation.ExchangeResult
import mesh.shadowmesh.attestation.toCredentialAttestation
import mesh.shadowmesh.bootstrap.PhysicalKeyExchange
import mesh.shadowmesh.bootstrap.QrIntroductionCode
import mesh.shadowmesh.bootstrap.nfc.BootstrapTrustLevel
import mesh.shadowmesh.bootstrap.nfc.NfcChallengeMessage
import mesh.shadowmesh.bootstrap.nfc.NfcFallback
import mesh.shadowmesh.bootstrap.nfc.NfcHandshake
import mesh.shadowmesh.bootstrap.nfc.NfcHandshakeStep
import mesh.shadowmesh.bootstrap.nfc.NfcResponseMessage
import mesh.shadowmesh.bootstrap.nfc.NfcTransport
import mesh.shadowmesh.crypto.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import mesh.shadowmesh.diagnostics.Diag
import kotlinx.coroutines.CoroutineScope

/**
 * NFC bootstrap coordinator — orchestrates the full QR + NFC physical trust flow.
 *
 * This is the single entry point for the UI layer. It drives both roles (initiator
 * and responder) through the complete 6-step protocol and surfaces state changes via
 * [state] StateFlow so the UI can react reactively.
 *
 * ## Roles
 *
 * **Initiator (QR generator, Device A)**:
 *   1. Call [startAsInitiator] — builds QR code, waits for NFC contact.
 *   2. Receive [BootstrapState.WaitingForNfc] — UI displays QR + "tap phones" prompt.
 *   3. NFC contact fires [onNfcTagDiscovered] — verifies B's challenge, sends response.
 *   4. Receive [BootstrapState.NfcVerified] — issue TRUST_PHYSICAL credential.
 *
 * **Responder (QR scanner, Device B)**:
 *   1. Scan QR → call [startAsResponder] with the decoded [QrIntroductionCode].
 *   2. Receive [BootstrapState.WaitingForNfc] — UI shows "tap phones" prompt.
 *   3. HCE receives A's AID select → [onHceApduReceived] fires the handshake.
 *   4. Receive [BootstrapState.NfcVerified] — issue TRUST_PHYSICAL credential.
 *
 * ## Trust credential issuance
 *
 * The coordinator does not issue [TrustCredential] directly — it returns
 * [BootstrapResult] from [awaitResult], which the caller passes to
 * [TrustCredentialSigner.sign] with the appropriate [IntroductionMethod.PHYSICAL].
 *
 * ## Fallback integration
 *
 * When [NfcTransport.detectFallback] returns [NfcFallback.BLE_PROXIMITY] or
 * [NfcFallback.QR_ONLY_DEGRADED], the coordinator emits [BootstrapState.FallbackMode]
 * and immediately completes the exchange for the RESPONDER side using the QR code data:
 *   BLE_PROXIMITY    → [BootstrapResult.Success] at [BootstrapTrustLevel.TRUST_PHYSICAL_BLE]
 *   QR_ONLY_DEGRADED → [BootstrapResult.Success] at [BootstrapTrustLevel.TRUST_INTRODUCED_QR_ONLY]
 * The INITIATOR does not complete in fallback mode — without NFC or BLE, there is no
 * back-channel to receive the responder's identity. Only the QR scanner earns a credential.
 */
class NfcBootstrapCoordinator(
    private val localIdentity:          NodePublicIdentity,
    private val localPrivateKey:        HybridSigningKey,
    private val baseExchange:           PhysicalKeyExchange,
    private val nfcHandshake:           NfcHandshake,
    private val scope:                  CoroutineScope,
    private val attestedExchange:       AttestedPhysicalExchange,
    /**
     * Application context — used by [NfcTransport.detectFallback] to check NFC and BLE
     * hardware availability. Application context (not Activity) is safe here since the
     * coordinator is singleton-scoped and must not hold an Activity reference.
     */
    private val context:                android.content.Context,
    /**
     * When true, the bootstrap is aborted if the peer cannot provide a valid hardware
     * attestation chain. When false (default), attestation failure is non-fatal —
     * the exchange succeeds at [BootstrapTrustLevel.TRUST_PHYSICAL_NFC] instead of
     * [BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED]. Set true only in high-security
     * deployments where all devices are known to have functional TEEs.
     */
    private val requireAttestation:     Boolean = false
) {
    private val _state = MutableStateFlow<BootstrapState>(BootstrapState.Idle)
    val state: StateFlow<BootstrapState> = _state.asStateFlow()

    // Mutex serialising all state mutations: startAsInitiator, startAsResponder,
    // onNfcTagDiscovered, onHceApduReceived, and reset.
    //
    // Fix #58: without this, concurrent calls (e.g. reset() from the UI while
    // onHceApduReceived fires from the HCE service) can interleave reads and writes
    // of plain var fields (currentQrCode, resultDeferred, localAttestationEvidence,
    // sentAttestationChallenge), producing NPEs or completing the wrong deferred.
    //
    // NFC taps and user-initiated resets are rare but not impossible: the user can
    // tap back while an NFC exchange is mid-flight. Mutex cost is negligible.
    private val stateMutex = kotlinx.coroutines.sync.Mutex()

    private var currentQrCode:           QrIntroductionCode? = null
    private var currentRole:             BootstrapRole       = BootstrapRole.INITIATOR
    private var resultDeferred:          kotlinx.coroutines.CompletableDeferred<BootstrapResult>? = null

    // ── Proximity gate ─────────────────────────────────────────────────────
    //
    // Security invariant: the NFC handshake MUST NOT proceed unless BleProximityScanner
    // has confirmed the peer is physically adjacent in this session. This prevents the
    // NFC bootstrap from being triggered remotely (relay attack) by an adversary who
    // somehow intercepts or replays the QR code from a distance.
    //
    // Set by confirmProximity() — called from OnboardingViewModel when BleProximityScanner
    // emits ProximityState.Confirmed for this session's target node ID.
    // Reset to false in reset() so a new session always starts unconfirmed.
    @Volatile private var proximityConfirmedForSession: Boolean = false

    /**
     * Signals that BLE proximity confirmation has been obtained for this session.
     * Must be called before [onNfcChallengeReceived] or [onHceApduReceived] will
     * proceed; both entry points return early if this has not been called.
     *
     * Thread-safe: [proximityConfirmedForSession] is @Volatile.
     */
    fun confirmProximity() {
        proximityConfirmedForSession = true
    }

    // Attestation state held across the async NFC tap.
    // @Volatile: written by the inner scope.launch in startAsResponder (outside the mutex lock
    // because the launch runs after the mutex is released) and read by onHceApduReceived
    // (which holds stateMutex). Without @Volatile, the JVM may cache the null value in the
    // reading thread's register and never observe the write. @Volatile ensures the write is
    // immediately visible to all threads. All accesses that need atomicity are additionally
    // protected by stateMutex; @Volatile covers the visibility gap on reference writes.
    /** Local attestation evidence generated against the peer's QR challenge. Set by responder eagerly. */
    @Volatile private var localAttestationEvidence: AttestationEvidence? = null
    /** Challenge this device sent to the peer for them to attest against. Set by responder. */
    @Volatile private var sentAttestationChallenge: ByteArray? = null

    // ── Initiator path ─────────────────────────────────────────────────────

    /**
     * Start as initiator (QR generator). Builds the QR code and enters waiting state.
     *
     * @return [QrIntroductionCode] — display this as a QR code in the UI.
     *         The UI transitions to "tap phones" mode after QR is shown.
     */
    suspend fun startAsInitiator(): QrIntroductionCode = stateMutex.withLock {
        currentRole = BootstrapRole.INITIATOR
        val qr = baseExchange.buildQrIntroductionCode(localIdentity, localPrivateKey)
            .getOrThrow()
        currentQrCode = qr
        resultDeferred = kotlinx.coroutines.CompletableDeferred()

        val fallback = mesh.shadowmesh.bootstrap.nfc.NfcTransport.detectFallback(context)
        if (fallback == mesh.shadowmesh.bootstrap.nfc.NfcFallback.NFC_AVAILABLE) {
            _state.value = BootstrapState.WaitingForNfc(
                role   = BootstrapRole.INITIATOR,
                prompt = "Show this QR code, then hold your phone close to your contact's phone."
            )
        } else {
            // NFC unavailable — the initiator displays the QR code but cannot complete the
            // exchange: without NFC or BLE, there is no back-channel for the responder to
            // send their identity. The resultDeferred stays open; the UI should inform the user
            // that only the QR scanner (their contact) will earn a trust credential this session.
            val warning = mesh.shadowmesh.bootstrap.nfc.NfcTransport.userPrompt(fallback)
            _state.value = BootstrapState.FallbackMode(fallback, warning)
            Diag.degraded("nfc-bootstrap", "initiator-fallback",
                "NFC unavailable on initiator device ($fallback) — exchange is one-sided. " +
                "The QR scanner will earn trust; initiator cannot complete without NFC/BLE contact.",
                "fallback" to fallback.name)
        }
        return qr
    }

    // ── Responder path ─────────────────────────────────────────────────────

    /**
     * Start as responder (QR scanner). Called after scanning A's QR code.
     *
     * @param qrCode The verified [QrIntroductionCode] from [PhysicalKeyExchange.receiveQrCode].
     */
    fun startAsResponder(qrCode: QrIntroductionCode) {
        scope.launch {
            stateMutex.withLock {
                currentRole   = BootstrapRole.RESPONDER
                currentQrCode = qrCode
                resultDeferred = kotlinx.coroutines.CompletableDeferred()

                val fallback = mesh.shadowmesh.bootstrap.nfc.NfcTransport.detectFallback(context)
                when (fallback) {
                    mesh.shadowmesh.bootstrap.nfc.NfcFallback.NFC_AVAILABLE -> {
                        _state.value = BootstrapState.WaitingForNfc(
                            role   = BootstrapRole.RESPONDER,
                            prompt = "Hold your phone close to your contact's phone to complete verification."
                        )
                        // Eagerly generate B's attestation evidence bound to A's QR challenge.
                        // TEE key generation can take ~200-500ms — run concurrently with prompt.
                        scope.launch {
                            localAttestationEvidence = when (
                                val r = attestedExchange.generateLocalAttestation(qrCode.attestationChallenge)
                            ) {
                                is AttestationResult.Evidence -> r.attestation
                                else                          -> null
                            }
                        }
                    }
                    mesh.shadowmesh.bootstrap.nfc.NfcFallback.BLE_PROXIMITY,
                    mesh.shadowmesh.bootstrap.nfc.NfcFallback.QR_ONLY_DEGRADED -> {
                        // NFC unavailable. The responder CAN complete the exchange because they
                        // have the initiator's identity from the QR code. The trust level is
                        // reduced: TRUST_PHYSICAL_BLE (BLE proximity, strong) or
                        // TRUST_INTRODUCED_QR_ONLY (QR only, weakest — no proximity verification).
                        val warning = mesh.shadowmesh.bootstrap.nfc.NfcTransport.userPrompt(fallback)
                        _state.value = BootstrapState.FallbackMode(fallback, warning)
                        completeFallbackAsResponder(qrCode, fallback)
                    }
                }
            }
        }
    }

    /**
     * Complete the bootstrap exchange using QR data only, without NFC contact.
     *
     * The responder already has the initiator's [nodeId] and [ed25519PubKey] from the QR code,
     * so they can issue a trust credential without an NFC back-channel. Trust level is
     * [BootstrapTrustLevel.TRUST_PHYSICAL_BLE] when BLE adjacency is detectable, or
     * [BootstrapTrustLevel.TRUST_INTRODUCED_QR_ONLY] for QR-only mode where no proximity
     * signal is available.
     *
     * Note: the initiator does NOT learn the responder's identity from this exchange —
     * there is no back-channel to deliver the responder's nodeId without NFC or BLE.
     * Only the responder earns a trust credential in this path.
     */
    private fun completeFallbackAsResponder(
        qrCode:   QrIntroductionCode,
        fallback: mesh.shadowmesh.bootstrap.nfc.NfcFallback
    ) {
        val trustLevel = when (fallback) {
            mesh.shadowmesh.bootstrap.nfc.NfcFallback.BLE_PROXIMITY    -> {
                // SECURITY: BLE_PROXIMITY requires a verified BLE RSSI-based distance check
                // to ensure the peer is physically nearby (< ~10 m). That check is not yet
                // implemented — the GATT handshake proves key possession but not proximity.
                // Without proximity verification, a peer on the same WiFi network could
                // trigger this code path and receive TRUST_PHYSICAL_BLE without being close.
                // Until BLE proximity verification is implemented, degrade to QR_ONLY so the
                // trust level accurately reflects what was cryptographically proven.
                Diag.degraded("nfc-bootstrap", "ble-proximity-not-verified",
                    "BLE_PROXIMITY fallback active but no RSSI distance check performed — " +
                    "downgrading to TRUST_INTRODUCED_QR_ONLY for safety")
                BootstrapTrustLevel.TRUST_INTRODUCED_QR_ONLY
            }
            mesh.shadowmesh.bootstrap.nfc.NfcFallback.QR_ONLY_DEGRADED -> BootstrapTrustLevel.TRUST_INTRODUCED_QR_ONLY
            mesh.shadowmesh.bootstrap.nfc.NfcFallback.NFC_AVAILABLE    -> return  // unreachable
        }
        Diag.info("nfc-bootstrap", "fallback-complete",
            "Bootstrap completed via fallback ($fallback) at $trustLevel. " +
            "Responder earned trust for initiator — initiator's back-channel unavailable.",
            "peerNodeId" to qrCode.nodeId.toHex().take(8), "trustLevel" to trustLevel.name)
        resultDeferred?.complete(
            BootstrapResult.Success(
                peerNodeId           = qrCode.nodeId,
                peerEd25519Key       = qrCode.ed25519PubKey,
                trustLevel           = trustLevel,
                sessionKey           = null,   // no shared session key without NFC handshake
                peerAttestationLevel = null
            )
        )
        // Transition to NfcVerified so the NavGraph LaunchedEffect (which only watches
        // NfcVerified/Failed) fires and calls onPhysicalPeerBootstrapped(). Without this,
        // FallbackMode completes the deferred but the contact is never stored — the sheet
        // stays open indefinitely on devices without NFC (including emulators).
        _state.value = BootstrapState.NfcVerified(
            role       = BootstrapRole.RESPONDER,
            peerNodeId = qrCode.nodeId,
            trustLevel = trustLevel
        )
    }

    // ── NFC event entry points ─────────────────────────────────────────────

    /**
     * Called by the Android NFC foreground dispatch (initiator role — NFC reader).
     * [rawApduPayload] is the payload extracted from the peer's HCE response APDU.
     *
     * Drives the initiator side of the handshake:
     *   - Parses the [NfcChallengeMessage] from B
     *   - Calls [NfcHandshake.verifyAndRespond]
     *   - Returns the [NfcResponseMessage] to send back over NFC
     *   - On success, completes [resultDeferred] with [BootstrapResult.Success]
     *
     * @return The [NfcResponseMessage] bytes to send back to B, or null on failure.
     */
    suspend fun onNfcChallengeReceived(rawApduPayload: ByteArray): ByteArray? {
        if (!proximityConfirmedForSession) {
            Diag.degraded("nfc-bootstrap", "proximity-gate",
                "NFC handshake blocked — BLE proximity not yet confirmed for this session")
            return null
        }
        val qr = currentQrCode ?: return null
        return try {
            val challenge = NfcChallengeMessage.fromBytes(rawApduPayload)

            // ── Attestation: verify B's evidence, generate A's evidence ────────────

            // Verify B's attestation evidence against the challenge A embedded in the QR.
            // B generated its TEE key bound to qr.attestationChallenge — if the chain
            // is valid, we know B's device ran the real app on verified hardware.
            val challengeEvidence = challenge.attestationEvidence
            val peerAttestationResult: ExchangeResult =
                if (challengeEvidence != null) {
                    attestedExchange.verifyPeerAttestation(
                        evidence        = deserialiseAttestationEvidence(challengeEvidence),
                        challengeWeSent = qr.attestationChallenge
                    )
                } else {
                    ExchangeResult.AttestationUnavailable("Peer sent no attestation evidence")
                }

            // Gate: abort if attestation is mandatory and peer failed
            if (requireAttestation && peerAttestationResult !is ExchangeResult.AttestationVerified) {
                val reason = when (peerAttestationResult) {
                    is ExchangeResult.AttestationFailed      -> peerAttestationResult.reason
                    is ExchangeResult.AttestationUnavailable -> peerAttestationResult.reason
                    else                                     -> "unknown"
                }
                _state.value = BootstrapState.Failed("Attestation required but peer failed: $reason")
                resultDeferred?.complete(BootstrapResult.Failed("Peer attestation failed: $reason"))
                return null
            }

            // Generate A's attestation evidence bound to B's challenge (if B sent one).
            // This is embedded in A's NFC response so B can verify A's hardware in turn.
            val myEvidence: ByteArray? = challenge.attestationChallengeForPeer?.let { bChallenge ->
                when (val r = attestedExchange.generateLocalAttestation(bChallenge)) {
                    is AttestationResult.Evidence -> serialiseAttestationEvidence(r.attestation)
                    else                          -> null
                }
            }

            // ── Trust level from attestation outcome ────────────────────────────────
            val trustLevel = when (peerAttestationResult) {
                is ExchangeResult.AttestationVerified -> BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED
                else                                  -> BootstrapTrustLevel.TRUST_PHYSICAL_NFC
            }

            // ── Continue with existing NFC handshake ────────────────────────────────
            val step = nfcHandshake.verifyAndRespond(
                localIdentity   = localIdentity,
                localPrivateKey = localPrivateKey,
                localQrNonce    = qr.nonce,
                peerMessage     = challenge,
                localAttestation = myEvidence
            ).getOrThrow()

            when (step) {
                is NfcHandshakeStep.InitiatorResponse -> {
                    _state.value = BootstrapState.NfcVerified(
                        role       = BootstrapRole.INITIATOR,
                        peerNodeId = step.verifiedPeerNodeId,
                        trustLevel = trustLevel
                    )
                    resultDeferred?.complete(
                        BootstrapResult.Success(
                            peerNodeId           = step.verifiedPeerNodeId,
                            peerEd25519Key       = step.verifiedPeerEd25519Key,
                            trustLevel           = trustLevel,
                            sessionKey           = buildSessionKey(
                                nonceA     = qr.nonce,
                                nonceB     = challenge.challengeNonce,
                                peerNodeId = step.verifiedPeerNodeId
                            ),
                            peerAttestationLevel = (peerAttestationResult as?
                                ExchangeResult.AttestationVerified)?.attestationLevel
                        )
                    )
                    step.message.toBytes()
                }
                else -> null
            }
        } catch (e: Exception) {
            Diag.swallowed("nfc-bootstrap", "challenge-recv", e)
            _state.value = BootstrapState.Failed("NFC handshake failed: ${e.message}")
            resultDeferred?.complete(BootstrapResult.Failed(e.message ?: "NFC error"))
            null
        }
    }

    /**
     * Called by the HCE service (responder role) when an APDU is received from A.
     *
     * Drives the responder side:
     *   - Builds the [NfcChallengeMessage] (first tap)
     *   - Verifies A's [NfcResponseMessage] (second tap / same connection)
     *   - On success, completes [resultDeferred]
     *
     * @return The APDU payload bytes to send back to A.
     */
    suspend fun onHceApduReceived(apduPayload: ByteArray): ByteArray = stateMutex.withLock {
        if (!proximityConfirmedForSession) {
            Diag.degraded("nfc-bootstrap", "proximity-gate",
                "HCE APDU blocked — BLE proximity not yet confirmed for this session")
            return NfcTransport.SW_NOT_FOUND
        }
        val qr = currentQrCode ?: return NfcTransport.SW_NOT_FOUND

        // Snapshot _state.value once. Using _state.value twice (check + cast) is a
        // TOCTOU: startAsResponder's _state.value write now happens inside stateMutex,
        // but a future refactor or subclass could reintroduce an unsynchronized write.
        // Snapshotting eliminates the double-read entirely and makes the cast infallible.
        val snap = _state.value
        return when (snap) {
            is BootstrapState.WaitingForNfc -> {
                // First contact: A is selecting our AID. Build challenge message.
                // Include B's attestation evidence (generated eagerly in startAsResponder)
                // and a fresh challenge for A to attest against.
                try {
                    val bChallengeForA = attestedExchange.generateChallenge()
                    sentAttestationChallenge = bChallengeForA

                    val challengeMsg = nfcHandshake.buildChallengeMessage(
                        localIdentity        = localIdentity,
                        localPrivateKey      = localPrivateKey,
                        qrCode               = qr,
                        attestationEvidence  = localAttestationEvidence?.let {
                            serialiseAttestationEvidence(it)
                        },
                        attestationChallengeForPeer = bChallengeForA
                    ).getOrThrow()

                    _state.value = BootstrapState.NfcChallengeExchanged(
                        sentNonce = challengeMsg.challengeNonce
                    )
                    challengeMsg.toBytes()
                } catch (e: Exception) {
                    Diag.swallowed("nfc-bootstrap", "build-challenge", e)
                    _state.value = BootstrapState.Failed("Failed to build NFC challenge: ${e.message}")
                    NfcTransport.SW_NOT_FOUND
                }
            }

            is BootstrapState.NfcChallengeExchanged -> {
                // Second message: A's response. Verify it, including A's attestation evidence.
                // snap is smart-cast to NfcChallengeExchanged by the when branch — no explicit cast needed.
                val challengeState = snap
                try {
                    val response = NfcResponseMessage.fromBytes(apduPayload)

                    // Verify A's attestation evidence against the challenge B sent
                    val responseEvidence = response.attestationEvidence
                    val peerAttestationResult: ExchangeResult =
                        if (responseEvidence != null && sentAttestationChallenge != null) {
                            attestedExchange.verifyPeerAttestation(
                                evidence        = deserialiseAttestationEvidence(responseEvidence),
                                challengeWeSent = sentAttestationChallenge!!
                            )
                        } else {
                            ExchangeResult.AttestationUnavailable("Initiator sent no attestation evidence")
                        }

                    if (requireAttestation && peerAttestationResult !is ExchangeResult.AttestationVerified) {
                        val reason = when (peerAttestationResult) {
                            is ExchangeResult.AttestationFailed      -> peerAttestationResult.reason
                            is ExchangeResult.AttestationUnavailable -> peerAttestationResult.reason
                            else                                     -> "unknown"
                        }
                        _state.value = BootstrapState.Failed("Attestation required but initiator failed: $reason")
                        resultDeferred?.complete(BootstrapResult.Failed("Initiator attestation failed: $reason"))
                        return NfcTransport.SW_NOT_FOUND
                    }

                    val trustLevel = when (peerAttestationResult) {
                        is ExchangeResult.AttestationVerified -> BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED
                        else                                  -> BootstrapTrustLevel.TRUST_PHYSICAL_NFC
                    }

                    val step = nfcHandshake.verifyResponse(
                        localChallengeNonce = challengeState.sentNonce,
                        peerResponse        = response,
                        qrCode              = qr
                    ).getOrThrow()

                    when (step) {
                        is NfcHandshakeStep.HandshakeComplete -> {
                            _state.value = BootstrapState.NfcVerified(
                                role       = BootstrapRole.RESPONDER,
                                peerNodeId = step.verifiedPeerNodeId,
                                trustLevel = trustLevel
                            )
                            resultDeferred?.complete(
                                BootstrapResult.Success(
                                    peerNodeId           = step.verifiedPeerNodeId,
                                    peerEd25519Key       = step.verifiedPeerEd25519Key,
                                    trustLevel           = trustLevel,
                                    sessionKey           = null,
                                    peerAttestationLevel = (peerAttestationResult as?
                                        ExchangeResult.AttestationVerified)?.attestationLevel
                                )
                            )
                            NfcTransport.SW_OK
                        }
                        else -> NfcTransport.SW_NOT_FOUND
                    }
                } catch (e: Exception) {
                    Diag.swallowed("nfc-bootstrap", "verify-response", e)
                    _state.value = BootstrapState.Failed("NFC response verification failed: ${e.message}")
                    resultDeferred?.complete(BootstrapResult.Failed(e.message ?: "NFC error"))
                    NfcTransport.SW_NOT_FOUND
                }
            }

            else -> NfcTransport.SW_NOT_FOUND
        }
    }

    /** Await the final result. Suspends until the handshake completes or fails. */
    suspend fun awaitResult(): BootstrapResult =
        resultDeferred?.await() ?: BootstrapResult.Failed("Not started")

    /**
     * Cancel any in-progress bootstrap and return to [BootstrapState.Idle].
     *
     * Cancels [resultDeferred] before nulling it — any coroutine suspended on
     * [awaitResult] receives a [kotlinx.coroutines.CancellationException] rather
     * than suspending forever.
     *
     * This function is suspend so callers (e.g. [OnboardingViewModel.retryBootstrap])
     * launch it via [kotlinx.coroutines.CoroutineScope.launch] rather than using
     * runBlocking.  Using runBlocking from a UI action risks blocking the main thread
     * if [onHceApduReceived] holds [stateMutex] on the NFC service thread concurrently.
     */
    suspend fun reset() = stateMutex.withLock {
        // Cancel before null — any caller suspended on awaitResult() is unblocked.
        resultDeferred?.cancel()
        currentQrCode               = null
        resultDeferred              = null
        localAttestationEvidence    = null
        sentAttestationChallenge    = null
        proximityConfirmedForSession = false
        _state.value                = BootstrapState.Idle
    }

    // ── Attestation serialisation helpers ─────────────────────────────────
    // AttestationEvidence is not a wire type in core:attestation — it holds ByteArray
    // fields. We serialise it for embedding in NFC messages using a simple length-prefixed
    // format. No external library needed — the same byte helpers used elsewhere.

    private fun serialiseAttestationEvidence(ev: AttestationEvidence): ByteArray {
        val chainBytes = ev.certificateChain.fold(ByteArray(0)) { acc, cert ->
            acc + intTo4Bytes(cert.size) + cert
        }
        return intTo4Bytes(ev.challenge.size) + ev.challenge +
               intTo4Bytes(ev.certificateChain.size) + chainBytes +
               intTo4Bytes(ev.publicKeyDer.size) + ev.publicKeyDer
    }

    private fun deserialiseAttestationEvidence(bytes: ByteArray): AttestationEvidence {
        var off = 0
        val challengeLen = readInt4(bytes, off); off += 4
        val challenge = bytes.copyOfRange(off, off + challengeLen); off += challengeLen
        val chainCount = readInt4(bytes, off); off += 4
        val chain = (0 until chainCount).map {
            val len = readInt4(bytes, off); off += 4
            bytes.copyOfRange(off, off + len).also { off += len }
        }
        val pubkeyLen = readInt4(bytes, off); off += 4
        val pubkey = bytes.copyOfRange(off, off + pubkeyLen)
        return AttestationEvidence(challenge, chain, pubkey)
    }


    /**
     * Derive the ephemeral NFC session key. [peerNodeId] MUST be the peer's verified
     * node id (from [NfcHandshakeStep.InitiatorResponse.verifiedPeerNodeId]) — it is
     * folded into the HKDF salt so both sides derive the same key bound to both
     * identities. Passing a placeholder (e.g. zeros) would weaken the binding and risk
     * a key mismatch with the peer, so this guards against an all-zero id.
     */
    private fun buildSessionKey(
        nonceA:     ByteArray,
        nonceB:     ByteArray,
        peerNodeId: ByteArray
    ): ByteArray {
        require(peerNodeId.size == 32 && peerNodeId.any { it != 0.toByte() }) {
            "peerNodeId must be the verified 32-byte peer id, not a placeholder"
        }
        return nfcHandshake.buildSessionKey(
            nonceA      = nonceA,
            nonceB      = nonceB,
            localNodeId = localIdentity.nodeId,
            peerNodeId  = peerNodeId
        )
    }
}

// ── State model ───────────────────────────────────────────────────────────────

sealed class BootstrapState {
    object Idle : BootstrapState()

    data class WaitingForNfc(
        val role:   BootstrapRole,
        val prompt: String
    ) : BootstrapState()

    /** Intermediate state: responder has sent its challenge, waiting for initiator's response. */
    data class NfcChallengeExchanged(
        val sentNonce: ByteArray
    ) : BootstrapState()

    data class NfcVerified(
        val role:       BootstrapRole,
        val peerNodeId: ByteArray,
        val trustLevel: BootstrapTrustLevel
    ) : BootstrapState()

    data class FallbackMode(
        val fallback: NfcFallback,
        val warning:  String
    ) : BootstrapState()

    data class Failed(val reason: String) : BootstrapState()
}

enum class BootstrapRole { INITIATOR, RESPONDER }

sealed class BootstrapResult {
    data class Success(
        val peerNodeId:           ByteArray,
        val peerEd25519Key:       ByteArray,
        val trustLevel:           BootstrapTrustLevel,
        /** Ephemeral session key for this NFC session, or null if not derived. */
        val sessionKey:           ByteArray?,
        /**
         * Hardware attestation tier achieved for the peer, or null if no attestation
         * was performed. Stored in the TrustCredential extension field so future
         * challengers can inspect the hardware tier that was verified at bootstrap time.
         */
        val peerAttestationLevel: AttestationTrustLevel?
    ) : BootstrapResult() {

        /**
         * Build the [TrustCredential.Unsigned] for this bootstrap result.
         *
         * Always use this factory instead of calling [TrustCredential.physical] or
         * [TrustCredential.physicalAttested] directly — it ensures the attestation tier
         * is threaded into the signed payload and can never be silently dropped.
         *
         * The returned unsigned credential must be signed via [TrustCredentialSigner.sign]
         * before storage or transmission.
         *
         * @param myNodeId  The local node's 32-byte identity (the introducer).
         */
        fun toUnsignedCredential(
            myNodeId: ByteArray
        ): mesh.shadowmesh.crypto.TrustCredential.Unsigned {
            val attestation = peerAttestationLevel
                ?.toCredentialAttestation()
                ?: mesh.shadowmesh.crypto.CredentialAttestation.NONE
            return mesh.shadowmesh.crypto.TrustCredential.physicalAttested(
                nodeId           = peerNodeId,
                introducerNodeId = myNodeId,
                attestation      = attestation
            )
        }
    }

    data class Failed(val reason: String) : BootstrapResult()
}
