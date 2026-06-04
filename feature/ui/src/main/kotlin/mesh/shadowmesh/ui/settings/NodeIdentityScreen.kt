package mesh.shadowmesh.ui.settings

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

@Composable
fun NodeIdentityScreen(
    nodeId:    String,
    qrBitmap:  Bitmap?,
    onBack:    () -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Clr.Bg0)
    ) {
        // ── Header ────────────────────────────────────────────────────────
        Row(
            Modifier
                .fillMaxWidth()
                .background(Clr.Bg1)
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, null, tint = Clr.TextSec)
            }
            Text(
                "NODE IDENTITY",
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 13.sp,
                color         = Clr.TextPri,
                letterSpacing = 0.1.sp,
            )
        }

        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // QR code
            if (qrBitmap != null) {
                Box(
                    Modifier
                        .size(220.dp)
                        .background(Color.White, RoundedCornerShape(12.dp))
                        .padding(12.dp),
                ) {
                    Image(
                        bitmap             = qrBitmap.asImageBitmap(),
                        contentDescription = "Node identity QR",
                        modifier           = Modifier.fillMaxSize(),
                    )
                }
            } else {
                Box(
                    Modifier
                        .size(220.dp)
                        .background(Clr.Bg3, RoundedCornerShape(12.dp))
                        .border(1.dp, Clr.Border, RoundedCornerShape(12.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("⧗", fontFamily = MonoFamily, fontSize = 32.sp, color = Clr.TextMute)
                }
            }

            Spacer(Modifier.height(20.dp))

            Text(
                "YOUR NODE ID",
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 9.sp,
                color         = Clr.TextMute,
                letterSpacing = 0.1.sp,
            )
            Spacer(Modifier.height(8.dp))

            // Full node ID split into blocks for readability
            val chunks = nodeId.chunked(8)
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Clr.Bg2, RoundedCornerShape(8.dp))
                    .border(1.dp, Clr.Border, RoundedCornerShape(8.dp))
                    .padding(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                chunks.chunked(4).forEach { line ->
                    Text(
                        line.joinToString(" "),
                        fontFamily    = MonoFamily,
                        fontSize      = 11.sp,
                        color         = Clr.Green,
                        letterSpacing = 0.04.sp,
                        textAlign     = TextAlign.Center,
                    )
                }
            }

            Spacer(Modifier.height(20.dp))

            // Explanation
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Clr.Bg2, RoundedCornerShape(8.dp))
                    .border(1.dp, Clr.Border, RoundedCornerShape(8.dp))
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                InfoLine(
                    "DERIVED FROM",
                    "Device Keystore secret + APK binding hash",
                )
                InfoLine(
                    "BINDING",
                    "Unique per device + build. Repackaged APK = different ID.",
                )
                InfoLine(
                    "SHARING",
                    "Share this QR to let contacts verify they are messaging the right node.",
                )
                InfoLine(
                    "PRIVACY",
                    "Your ID is visible to peers you contact. It is NOT broadcast to the wider mesh.",
                )
            }
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            label,
            fontFamily = MonoFamily,
            fontSize   = 9.sp,
            color      = Clr.TextMute,
            modifier   = Modifier.width(90.dp),
            letterSpacing = 0.06.sp,
        )
        Text(
            value,
            fontFamily = MonoFamily,
            fontSize   = 9.sp,
            color      = Clr.TextSec,
            modifier   = Modifier.weight(1f),
        )
    }
}
