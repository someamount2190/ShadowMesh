package mesh.shadowmesh.ui.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import mesh.shadowmesh.onboarding.OnboardingCompletionSummary
import mesh.shadowmesh.onboarding.OnboardingViewModel
import mesh.shadowmesh.onboarding.OnboardingViewModel.OnboardingStep
import mesh.shadowmesh.onboarding.PinSetupResult
import mesh.shadowmesh.platform.BiometricEnrollmentChecker.EnrollmentStatus
import mesh.shadowmesh.platform.VpnServiceBridge
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.graphics.asImageBitmap
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import mesh.shadowmesh.attestation.nfc.BootstrapState
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

// ── Root onboarding host ──────────────────────────────────────────────────────

@Composable
fun OnboardingHost(
    vm:          OnboardingViewModel = hiltViewModel(),
    onComplete:  () -> Unit,
) {
    val step       by vm.currentStep.collectAsStateWithLifecycle()
    val completed  by vm.completedSteps.collectAsStateWithLifecycle()

    Box(Modifier.fillMaxSize().background(Clr.Bg0)) {
        when (step) {
            OnboardingStep.WELCOME           -> WelcomeStep(onBegin = { vm.advance() })
            OnboardingStep.BIOMETRIC_CHECK   -> BiometricStep(vm)
            OnboardingStep.BATTERY_EXEMPTION -> BatteryStep(vm)
            OnboardingStep.VPN_PERMISSION    -> VpnStep(vm)
            OnboardingStep.DURESS_PIN_SETUP  -> DuressPinStep(vm)
            OnboardingStep.ENTRY_NODE_SETUP  -> EntryNodeStep(vm)
            OnboardingStep.COMPLETE          -> CompleteStep(vm, onComplete)
            else                             -> { /* PHYSICAL_EXCHANGE not shown in onboarding */ }
        }
    }
}

// ── Step shell — back arrow + progress dots ───────────────────────────────────

@Composable
private fun StepShell(
    stepIndex:  Int,      // 0-based, 0 = WELCOME (no header shown on WELCOME)
    totalSteps: Int = 7,
    onBack:     (() -> Unit)? = null,
    content:    @Composable ColumnScope.() -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Clr.Bg0)
            .verticalScroll(rememberScrollState())
    ) {
        // Header — back + progress
        if (stepIndex > 0) {
            Row(
                modifier          = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (onBack != null) {
                    Text(
                        "←",
                        color      = Clr.TextSec,
                        fontSize   = 18.sp,
                        modifier   = Modifier.clickable(onClick = onBack).padding(end = 12.dp),
                    )
                } else {
                    Spacer(Modifier.width(30.dp))
                }
                Text(
                    "Step $stepIndex of ${totalSteps - 1}",
                    color      = Clr.TextMute,
                    fontSize   = 11.sp,
                    fontFamily = MonoFamily,
                    modifier   = Modifier.padding(end = 10.dp),
                )
                // Progress dots
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    repeat(totalSteps - 1) { i ->
                        Box(
                            Modifier
                                .size(7.dp)
                                .background(
                                    if (i < stepIndex) Clr.Green else Clr.Bg4,
                                    RoundedCornerShape(50)
                                )
                        )
                    }
                }
            }
            HorizontalDivider(color = Clr.Border, thickness = 1.dp)
        }

        // Step content
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 28.dp),
            content  = content,
        )
    }
}

// ── Step 1: Welcome ───────────────────────────────────────────────────────────

@Composable
private fun WelcomeStep(onBegin: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Clr.Bg0)
            .padding(horizontal = 24.dp, vertical = 48.dp),
        verticalArrangement   = Arrangement.SpaceBetween,
    ) {
        Column {
            // Wordmark
            Text(
                "SHADOWMESH",
                color         = Clr.Green,
                fontSize      = 22.sp,
                fontWeight    = FontWeight.Bold,
                fontFamily    = MonoFamily,
                letterSpacing = 0.14.sp,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "A mesh forum with no servers,\nno accounts, and no records.",
                color      = Clr.TextSec,
                fontSize   = 14.sp,
                lineHeight = 20.sp,
            )

            Spacer(Modifier.height(28.dp))
            HorizontalDivider(color = Clr.Border)
            Spacer(Modifier.height(28.dp))

            Text(
                "Your messages are encrypted end-to-end and stored only on " +
                "devices that have earned physical trust.",
                color      = Clr.TextPri,
                fontSize   = 14.sp,
                lineHeight = 21.sp,
            )
            Spacer(Modifier.height(16.dp))
            Text(
                "No phone number. No email. No cloud.",
                color      = Clr.TextSec,
                fontSize   = 13.sp,
            )

            Spacer(Modifier.height(28.dp))
            HorizontalDivider(color = Clr.Border)
            Spacer(Modifier.height(28.dp))

            Text(
                "Setup takes about 3 minutes.",
                color      = Clr.TextMute,
                fontSize   = 12.sp,
                fontFamily = MonoFamily,
            )
        }

        PrimaryButton("Begin setup", onClick = onBegin)
    }
}

// ── Step 2: Biometric check ───────────────────────────────────────────────────

@Composable
private fun BiometricStep(vm: OnboardingViewModel) {
    val status     by vm.biometricStatus.collectAsStateWithLifecycle()
    val canProceed by vm.canProceedPastBiometric.collectAsStateWithLifecycle()
    val message    by vm.biometricMessage.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { vm.refreshBiometricStatus() }

    StepShell(stepIndex = 1, onBack = { vm.goBack() }) {
        StepTitle("Screen lock required")
        Spacer(Modifier.height(12.dp))
        Text(
            "Your encryption keys are stored in Android's secure hardware " +
            "and locked behind your screen lock.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(24.dp))

        // Status card
        val (cardBg, cardBord, checkColor, icon) = when (status) {
            EnrollmentStatus.STRONG_BIOMETRIC_READY ->
                StatusCard(Clr.GreenMute, Clr.Green, Clr.Green, "✓")
            EnrollmentStatus.WEAK_BIOMETRIC_ONLY,
            EnrollmentStatus.CREDENTIAL_ONLY        ->
                StatusCard(Clr.AmberMute, Clr.Amber, Clr.Amber, "⚠")
            else ->
                StatusCard(Clr.RedMute,   Clr.Red,   Clr.Red,   "✕")
        }

        Column(
            Modifier
                .fillMaxWidth()
                .background(cardBg, RoundedCornerShape(6.dp))
                .border(1.dp, cardBord.copy(0.5f), RoundedCornerShape(6.dp))
                .padding(14.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(icon, color = checkColor, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Text(
                    when (status) {
                        EnrollmentStatus.STRONG_BIOMETRIC_READY -> "Fingerprint enrolled"
                        EnrollmentStatus.WEAK_BIOMETRIC_ONLY    -> "Weak biometric only"
                        EnrollmentStatus.CREDENTIAL_ONLY        -> "PIN / password only"
                        EnrollmentStatus.NONE_ENROLLED          -> "No screen lock set"
                        else                                    -> "Unknown status"
                    },
                    color = Clr.TextPri, fontSize = 13.sp,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                when (status) {
                    EnrollmentStatus.STRONG_BIOMETRIC_READY -> "Hardware security: TEE"
                    EnrollmentStatus.WEAK_BIOMETRIC_ONLY    -> "Weak — will fall back to PIN for key operations"
                    EnrollmentStatus.CREDENTIAL_ONLY        -> "PIN accepted for key operations"
                    EnrollmentStatus.NONE_ENROLLED          -> "Must enroll a screen lock to continue"
                    else                                    -> "Could not determine status"
                },
                color = Clr.TextMute, fontSize = 11.sp, fontFamily = MonoFamily,
            )
        }

        Spacer(Modifier.height(16.dp))
        Text(message, color = Clr.TextSec, fontSize = 12.sp, lineHeight = 17.sp)
        Spacer(Modifier.height(32.dp))

        if (!canProceed) {
            PrimaryButton("Set up screen lock") { vm.openBiometricEnrollment() }
        } else {
            PrimaryButton("Continue") { vm.advance() }
        }
    }
}

private data class StatusCard(val bg: Color, val border: Color, val check: Color, val icon: String)

// ── Step 3: Battery exemption ─────────────────────────────────────────────────

@Composable
private fun BatteryStep(vm: OnboardingViewModel) {
    val exempted by vm.dozeExempted.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { vm.refreshDozeStatus() }

    StepShell(stepIndex = 2, onBack = { vm.goBack() }) {
        StepTitle("Background access")
        Spacer(Modifier.height(12.dp))
        Text(
            "SHADOWMESH needs to stay connected in the background to receive messages.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(24.dp))

        // AOSP status card
        StatusRow(
            label  = "Android battery optimization",
            status = if (exempted) "Exempt ✓" else "Not yet exempt",
            color  = if (exempted) Clr.Green else Clr.Amber,
        )

        Spacer(Modifier.height(12.dp))

        if (!exempted) {
            SecondaryButton("Request battery exemption") { vm.requestDozeExemption() }
            Spacer(Modifier.height(20.dp))
        }

        // OEM-specific instructions
        if (vm.hasOemExemptionScreen) {
            HorizontalDivider(color = Clr.Border)
            Spacer(Modifier.height(16.dp))
            Text(
                "${vm.oemRom.name.replace('_', ' ')} — additional step required",
                color = Clr.Amber, fontSize = 12.sp, fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(6.dp))
            Text(vm.oemInstruction, color = Clr.TextSec, fontSize = 12.sp, lineHeight = 18.sp)
            Spacer(Modifier.height(12.dp))
            SecondaryButton("Open ${vm.oemRom.name.replace('_',' ')} battery settings") {
                vm.openOemExemptionSettings()
            }
            Spacer(Modifier.height(20.dp))
        }

        PrimaryButton(
            text    = "Continue",
            enabled = exempted,
            onClick = { vm.advance() },
        )
        if (!exempted) {
            Spacer(Modifier.height(8.dp))
            Text(
                "Tap 'Request battery exemption' above, then return here.",
                color = Clr.TextMute, fontSize = 11.sp, textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

// ── Step 4: VPN permission ────────────────────────────────────────────────────

@Composable
private fun VpnStep(vm: OnboardingViewModel) {
    val permState by vm.vpnPermissionState.collectAsStateWithLifecycle()
    val granted   = permState == VpnServiceBridge.PermissionState.GRANTED

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        vm.onVpnConsentResult(result.resultCode == android.app.Activity.RESULT_OK)
    }

    StepShell(stepIndex = 3, onBack = { vm.goBack() }) {
        StepTitle("Circuit tunnel", tag = "optional")
        Spacer(Modifier.height(12.dp))
        Text(
            "The onion circuit routes your app traffic through the mesh so your IP is " +
            "not visible to the network.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "This requires a one-time VPN permission. Your traffic never leaves the mesh. " +
            "No external VPN server is used.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(28.dp))

        if (granted) {
            StatusRow("Circuit tunnel", "Authorized ✓", Clr.Green)
            Spacer(Modifier.height(24.dp))
            PrimaryButton("Continue") { vm.advance() }
        } else {
            PrimaryButton("Authorize circuit tunnel") {
                val intent = vm.prepareVpnConsent()
                if (intent != null) vpnConsentLauncher.launch(intent)
                // intent == null → already granted; prepareVpnConsent updated state directly
            }
        }
        Spacer(Modifier.height(16.dp))
        TextButton(
            onClick  = { vm.skipStep() },
            modifier = Modifier.align(Alignment.End),
        ) {
            Text("Skip", color = Clr.TextMute, fontSize = 12.sp)
        }
    }
}

// ── Step 5: Duress PIN setup ──────────────────────────────────────────────────

@Composable
private fun DuressPinStep(vm: OnboardingViewModel) {
    var realPin    by remember { mutableStateOf("") }
    var duressPin  by remember { mutableStateOf("") }
    var error      by remember { mutableStateOf<String?>(null) }
    var submitting by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        vm.pinSetupResult.collect { result ->
            submitting = false
            when (result) {
                is PinSetupResult.Success    -> { /* vm.advance() already called internally */ }
                is PinSetupResult.Error      -> error = result.message
            }
        }
    }

    StepShell(stepIndex = 4, onBack = { vm.goBack() }) {
        StepTitle("Duress PIN", tag = "optional")
        Spacer(Modifier.height(12.dp))
        Text(
            "If you are forced to unlock, enter your duress PIN. It shows a decoy " +
            "channel list and your real data remains hidden.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(28.dp))

        PinField(label = "Real PIN", value = realPin, onValueChange = {
            realPin = it; error = null
        })
        Spacer(Modifier.height(12.dp))
        PinField(label = "Duress PIN", value = duressPin, onValueChange = {
            duressPin = it; error = null
        })

        if (error != null) {
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("⚠", color = Clr.Amber, fontSize = 13.sp)
                Text(error!!, color = Clr.Amber, fontSize = 12.sp)
            }
        }

        Spacer(Modifier.height(28.dp))

        PrimaryButton(
            text    = if (submitting) "Setting up…" else "Set up duress PIN",
            enabled = realPin.isNotEmpty() && duressPin.isNotEmpty() && !submitting,
            onClick = {
                submitting = true
                error      = null
                // In production: deviceSecret from AppModule.deviceSecret
                vm.setupPins(
                    realPin   = realPin.toByteArray(),
                    duressPin = duressPin.toByteArray(),
                )
            }
        )
        Spacer(Modifier.height(12.dp))
        TextButton(
            onClick  = { vm.skipStep() },
            modifier = Modifier.align(Alignment.End),
        ) {
            Text("Skip", color = Clr.TextMute, fontSize = 12.sp)
        }
    }
}

// ── Step 6: Entry node setup ──────────────────────────────────────────────────

@Composable
private fun EntryNodeStep(vm: OnboardingViewModel) {
    StepShell(stepIndex = 5, onBack = { vm.goBack() }) {
        StepTitle("Entry Node", tag = "optional")
        Spacer(Modifier.height(12.dp))
        Text(
            "Your Entry Node knows your IP address and that you are active. " +
            "They know nothing else.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(16.dp))
        Text(
            "You should choose someone you physically trust. You will set this " +
            "up in the next step. For now, a random peer will be used.",
            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 19.sp,
        )
        Spacer(Modifier.height(24.dp))

        StatusRow("Current setting", "Random peer  (least private)", Clr.Amber)
        Spacer(Modifier.height(8.dp))
        Text(
            "You can configure this later in Settings → Privacy → Entry Node.",
            color = Clr.TextMute, fontSize = 11.sp, fontFamily = MonoFamily,
        )
        Spacer(Modifier.height(32.dp))

        PrimaryButton("I understand — continue") { vm.advance() }
        Spacer(Modifier.height(12.dp))
        TextButton(
            onClick  = { vm.skipStep() },
            modifier = Modifier.align(Alignment.End),
        ) {
            Text("Skip", color = Clr.TextMute, fontSize = 12.sp)
        }
    }
}

/**
 * Renders a QR code from raw bytes.
 *
 * Encodes [data] (base64) via ZXing [MultiFormatWriter] into a 512px bitmap, then
 * renders it as a Compose [Image]. Re-encodes only when [data] changes.
 *
 * Requires: com.google.zxing:core (already a transitive dep via barcode scanner).
 */
@Composable
internal fun QrBitmap(data: ByteArray, modifier: Modifier = Modifier) {
    val bitmap = remember(data) {
        runCatching {
            val encoded = android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP)
            val matrix  = com.google.zxing.MultiFormatWriter().encode(
                encoded, com.google.zxing.BarcodeFormat.QR_CODE, 512, 512
            )
            val w = matrix.width; val h = matrix.height
            val pixels = IntArray(w * h) { i ->
                if (matrix.get(i % w, i / w)) android.graphics.Color.BLACK
                else android.graphics.Color.WHITE
            }
            android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.RGB_565)
                .also { it.setPixels(pixels, 0, w, 0, 0, w, h) }
        }.getOrNull()
    }
    if (bitmap != null) {
        androidx.compose.foundation.Image(
            bitmap             = bitmap.asImageBitmap(),
            contentDescription = "QR code for contact to scan",
            modifier           = modifier
        )
    } else {
        Box(modifier, contentAlignment = Alignment.Center) {
            Text("QR unavailable", color = Clr.TextMute, fontSize = 10.sp)
        }
    }
}


// ── Step 8: Complete ──────────────────────────────────────────────────────────

@Composable
private fun CompleteStep(vm: OnboardingViewModel, onComplete: () -> Unit) {
    val summary by vm.completionSummary.collectAsStateWithLifecycle()

    StepShell(stepIndex = 6) {
        StepTitle("Setup complete")
        Spacer(Modifier.height(24.dp))

        // Summary lines
        summary.summaryLines().forEach { line ->
            val isComplete = line.startsWith("✓")
            val isOptional = line.startsWith("○")
            val color = when {
                isComplete -> Clr.Green
                isOptional -> Clr.TextMute
                else       -> Clr.Amber
            }
            Row(
                verticalAlignment     = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier              = Modifier.padding(vertical = 5.dp),
            ) {
                Text(
                    line.take(1),
                    color = color, fontSize = 14.sp, fontFamily = MonoFamily,
                    modifier = Modifier.width(16.dp),
                )
                Text(
                    line.drop(2),
                    color = if (isComplete) Clr.TextPri else Clr.TextSec,
                    fontSize = 13.sp, lineHeight = 18.sp,
                )
            }
        }

        Spacer(Modifier.height(24.dp))
        HorizontalDivider(color = Clr.Border)
        Spacer(Modifier.height(20.dp))

        // Protection score bar
        ProtectionBar(score = summary.protectionScore, total = 6)

        Spacer(Modifier.height(20.dp))
        Text(
            "You can adjust all of these in Settings at any time.",
            color = Clr.TextMute, fontSize = 12.sp,
        )
        Spacer(Modifier.height(36.dp))

        PrimaryButton("Enter SHADOWMESH", onClick = onComplete)
    }
}

// ── Shared widgets ────────────────────────────────────────────────────────────

@Composable
private fun StepTitle(title: String, tag: String? = null) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            title,
            color      = Clr.TextPri,
            fontSize   = 20.sp,
            fontWeight = FontWeight.SemiBold,
            lineHeight = 26.sp,
        )
        if (tag != null) {
            Text(
                tag,
                color      = Clr.TextMute,
                fontSize   = 11.sp,
                fontFamily = MonoFamily,
                modifier   = Modifier
                    .background(Clr.Bg3, RoundedCornerShape(3.dp))
                    .border(1.dp, Clr.Border, RoundedCornerShape(3.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp),
            )
        }
    }
}

@Composable
private fun StatusRow(label: String, status: String, color: Color) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg2, RoundedCornerShape(6.dp))
            .border(1.dp, Clr.Border, RoundedCornerShape(6.dp))
            .padding(12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically,
    ) {
        Text(label, color = Clr.TextSec, fontSize = 12.sp)
        Text(status, color = color, fontSize = 12.sp, fontFamily = MonoFamily,
            fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun PinField(label: String, value: String, onValueChange: (String) -> Unit) {
    Column {
        Text(label, color = Clr.TextSec, fontSize = 11.sp, fontFamily = MonoFamily,
            modifier = Modifier.padding(bottom = 6.dp))
        OutlinedTextField(
            value           = value,
            onValueChange   = { if (it.length <= 16) onValueChange(it) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            singleLine      = true,
            modifier        = Modifier.fillMaxWidth(),
            colors          = OutlinedTextFieldDefaults.colors(
                focusedBorderColor   = Clr.Green,
                unfocusedBorderColor = Clr.Border,
                focusedTextColor     = Clr.TextPri,
                unfocusedTextColor   = Clr.TextPri,
                cursorColor          = Clr.Green,
                focusedContainerColor   = Clr.Bg2,
                unfocusedContainerColor = Clr.Bg2,
            ),
        )
    }
}

@Composable
private fun ProtectionBar(score: Int, total: Int) {
    val label = when {
        score >= 5 -> "Strong"
        score >= 3 -> "Moderate"
        else       -> "Basic"
    }
    val barColor = when {
        score >= 5 -> Clr.Green
        score >= 3 -> Clr.Amber
        else       -> Clr.Red
    }
    Column {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Protection level: $score / $total",
                color = Clr.TextSec, fontSize = 12.sp, fontFamily = MonoFamily)
            Text(label, color = barColor, fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold, fontFamily = MonoFamily)
        }
        Spacer(Modifier.height(8.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(8.dp)
                .background(Clr.Bg4, RoundedCornerShape(4.dp))
        ) {
            Box(
                Modifier
                    .fillMaxWidth(score.toFloat() / total)
                    .fillMaxHeight()
                    .background(barColor, RoundedCornerShape(4.dp))
            )
        }
    }
}

@Composable
private fun PrimaryButton(
    text:    String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Button(
        onClick  = onClick,
        enabled  = enabled,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape    = RoundedCornerShape(6.dp),
        colors   = ButtonDefaults.buttonColors(
            containerColor         = Clr.Green,
            contentColor           = Color.Black,
            disabledContainerColor = Clr.Bg3,
            disabledContentColor   = Clr.TextMute,
        ),
    ) {
        Text(text, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SecondaryButton(text: String, onClick: () -> Unit) {
    OutlinedButton(
        onClick  = onClick,
        modifier = Modifier.fillMaxWidth().height(44.dp),
        shape    = RoundedCornerShape(6.dp),
        border   = ButtonDefaults.outlinedButtonBorder.copy(
            width = 1.dp,
        ),
        colors   = ButtonDefaults.outlinedButtonColors(contentColor = Clr.TextSec),
    ) {
        Text(text, fontSize = 13.sp)
    }
}
