// TODO: [BLE Redesign] proximityConfirmed + peerLabel params added.
// Three-stage bootstrap status display: Scanning → Found → Verified.
// ASSUMPTION: peerLabel is the peer's display name or a short node ID excerpt;
// null falls back to "nearby device". Supplied by NavGraph from the scanned QR.

package mesh.shadowmesh.ui.contacts

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.attestation.nfc.BootstrapState
import mesh.shadowmesh.ui.onboarding.QrBitmap
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

@Composable
fun AddContactSheet(
    bootstrapQrBytes:  ByteArray?,
    bootstrapState:    BootstrapState,
    bootstrapError:    String?,
    myNodeId:          String,
    onSubmitCode:      (String) -> Unit,
    onScanQr:          () -> Unit,
    onDismiss:         () -> Unit,
    /** True when BleProximityScanner has confirmed the peer is nearby this session. */
    proximityConfirmed: Boolean = false,
    /** Peer's display name or short node ID; shown in stage 1 prompt. */
    peerLabel:          String? = null,
    /** Called when the user taps COPY CODE — delivers the base64 node code string. */
    onCopyCode:         (String) -> Unit = {},
) {
    var tab by remember { mutableStateOf(0) }

    val isBusy = bootstrapState is BootstrapState.WaitingForNfc ||
                 bootstrapState is BootstrapState.NfcChallengeExchanged

    val isVerified = bootstrapState is BootstrapState.NfcVerified

    // Three-stage proximity label: Scanning → Found → Verified
    val (stageDot, stageText) = when {
        isVerified         -> Clr.Green to "Contact verified ✓"
        proximityConfirmed -> Clr.Green to "Found them. Tap phones to verify."
        bootstrapState is BootstrapState.Failed ->
            Clr.Red to "NFC failed"
        bootstrapState is BootstrapState.FallbackMode ->
            Clr.Amber to "NFC unavailable — BLE fallback"
        else               -> Clr.Amber to "Looking for ${peerLabel ?: "nearby device"}…"
    }

    Column(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg1)
            .padding(16.dp),
    ) {
        // ── Title row ─────────────────────────────────────────────────────
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                "ADD CONTACT",
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 13.sp,
                color         = Clr.TextPri,
                letterSpacing = 0.1.sp,
                modifier      = Modifier.weight(1f),
            )
            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, null, tint = Clr.TextMute)
            }
        }

        Spacer(Modifier.height(12.dp))

        // ── Tabs ──────────────────────────────────────────────────────────
        Row(
            Modifier
                .fillMaxWidth()
                .background(Clr.Bg2, RoundedCornerShape(6.dp))
                .padding(2.dp),
        ) {
            listOf("SHOW MY CODE", "SCAN / ENTER").forEachIndexed { i, label ->
                Box(
                    Modifier
                        .weight(1f)
                        .background(
                            if (tab == i) Clr.GreenMute else Color.Transparent,
                            RoundedCornerShape(4.dp),
                        )
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    TextButton(onClick = { tab = i }, modifier = Modifier.fillMaxWidth()) {
                        Text(
                            label,
                            fontFamily    = MonoFamily,
                            fontSize      = 10.sp,
                            fontWeight    = FontWeight.Bold,
                            color         = if (tab == i) Clr.Green else Clr.TextMute,
                            letterSpacing = 0.06.sp,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        when (tab) {
            0 -> ShowMyCodeTab(
                bootstrapQrBytes = bootstrapQrBytes,
                myNodeId         = myNodeId,
                stageDot         = stageDot,
                stageText        = stageText,
                bootstrapError   = bootstrapError,
                onCopyCode       = onCopyCode,
            )
            1 -> ScanEnterTab(
                isBusy  = isBusy,
                error   = bootstrapError,
                onScan  = onScanQr,
                onSubmit= onSubmitCode,
            )
        }

        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun ShowMyCodeTab(
    bootstrapQrBytes: ByteArray?,
    myNodeId:         String,
    stageDot:         androidx.compose.ui.graphics.Color,
    stageText:        String,
    bootstrapError:   String?,
    onCopyCode:       (String) -> Unit = {},
) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier
                .size(200.dp)
                .background(Color.White, RoundedCornerShape(8.dp))
                .padding(8.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (bootstrapQrBytes != null) {
                QrBitmap(
                    data     = bootstrapQrBytes,
                    modifier = Modifier.fillMaxSize(),
                )
            } else {
                CircularProgressIndicator(
                    color       = Clr.Green,
                    modifier    = Modifier.size(32.dp),
                    strokeWidth = 2.dp,
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        // Three-stage proximity + NFC status row
        Row(
            verticalAlignment     = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Box(
                Modifier
                    .size(8.dp)
                    .background(stageDot, RoundedCornerShape(50))
            )
            Text(
                stageText,
                fontFamily = MonoFamily,
                fontSize   = 10.sp,
                color      = Clr.TextMute,
            )
        }

        if (bootstrapError != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                "⚠ $bootstrapError",
                fontFamily = MonoFamily,
                fontSize   = 9.sp,
                color      = Clr.Red,
                modifier   = Modifier.fillMaxWidth()
                    .background(Clr.Red.copy(alpha = 0.08f), RoundedCornerShape(4.dp))
                    .padding(8.dp),
            )
        }

        Spacer(Modifier.height(8.dp))
        Text(
            "Show this QR to your contact. Hold phones together for NFC.",
            fontFamily = MonoFamily,
            fontSize   = 10.sp,
            color      = Clr.TextSec,
            modifier   = Modifier.padding(horizontal = 16.dp),
        )
        Spacer(Modifier.height(4.dp))
        Text(
            myNodeId.take(16) + "…",
            fontFamily    = MonoFamily,
            fontSize      = 9.sp,
            color         = Clr.TextMute,
            letterSpacing = 0.04.sp,
        )

        if (bootstrapQrBytes != null) {
            val clipboardManager = LocalClipboardManager.current
            Spacer(Modifier.height(12.dp))
            OutlinedButton(
                onClick = {
                    val b64 = android.util.Base64.encodeToString(bootstrapQrBytes, android.util.Base64.NO_WRAP)
                    clipboardManager.setText(AnnotatedString(b64))
                    onCopyCode(b64)
                },
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(6.dp),
                colors   = ButtonDefaults.outlinedButtonColors(contentColor = Clr.TextSec),
                border   = ButtonDefaults.outlinedButtonBorder.copy(width = 1.dp),
            ) {
                Text(
                    "COPY CODE",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 10.sp,
                    letterSpacing = 0.06.sp,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Paste in the other device's SCAN / ENTER tab",
                fontFamily = MonoFamily,
                fontSize   = 9.sp,
                color      = Clr.TextMute,
                modifier   = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ScanEnterTab(
    isBusy:   Boolean,
    error:    String?,
    onScan:   () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var code by remember { mutableStateOf("") }

    Column(Modifier.fillMaxWidth()) {
        // Camera scan button
        OutlinedButton(
            onClick  = onScan,
            enabled  = !isBusy,
            modifier = Modifier.fillMaxWidth(),
            shape    = RoundedCornerShape(6.dp),
            colors   = ButtonDefaults.outlinedButtonColors(contentColor = Clr.Green),
            border   = ButtonDefaults.outlinedButtonBorder.copy(width = 1.dp),
        ) {
            Text(
                "SCAN QR CODE",
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 11.sp,
                letterSpacing = 0.06.sp,
            )
        }

        Spacer(Modifier.height(14.dp))

        Text(
            "OR PASTE CODE",
            fontFamily    = MonoFamily,
            fontWeight    = FontWeight.Bold,
            fontSize      = 10.sp,
            color         = Clr.TextMute,
            letterSpacing = 0.08.sp,
        )
        Spacer(Modifier.height(8.dp))
        BasicTextField(
            value         = code,
            onValueChange = { code = it },
            modifier      = Modifier
                .fillMaxWidth()
                .height(80.dp)
                .background(Clr.Bg3, RoundedCornerShape(6.dp))
                .border(
                    1.dp,
                    if (error != null) Clr.Red else Clr.Border,
                    RoundedCornerShape(6.dp),
                )
                .padding(10.dp),
            textStyle = TextStyle(
                fontFamily = MonoFamily,
                fontSize   = 10.sp,
                color      = Clr.TextPri,
            ),
            cursorBrush = SolidColor(Clr.Green),
            decorationBox = { inner ->
                if (code.isEmpty()) {
                    Text(
                        "Paste the base64 node code from the other device…",
                        fontFamily = MonoFamily,
                        fontSize   = 10.sp,
                        color      = Clr.TextMute,
                    )
                }
                inner()
            }
        )
        if (error != null) {
            Spacer(Modifier.height(4.dp))
            Text(error, fontFamily = MonoFamily, fontSize = 9.sp, color = Clr.Red)
        }
        Spacer(Modifier.height(12.dp))
        Button(
            onClick          = { if (code.isNotBlank()) onSubmit(code.trim()) },
            enabled          = code.isNotBlank() && !isBusy,
            modifier         = Modifier.fillMaxWidth(),
            shape            = RoundedCornerShape(6.dp),
            colors           = ButtonDefaults.buttonColors(
                containerColor = Clr.GreenMute,
                contentColor   = Clr.Green,
            ),
        ) {
            if (isBusy) {
                CircularProgressIndicator(
                    Modifier.size(16.dp),
                    color       = Clr.Green,
                    strokeWidth = 2.dp,
                )
            } else {
                Text(
                    "CONNECT",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 11.sp,
                    letterSpacing = 0.06.sp,
                )
            }
        }
    }
}
