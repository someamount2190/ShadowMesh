package mesh.shadowmesh.ui.channels

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

private data class TypeOption(
    val type:        ChannelType,
    val label:       String,
    val description: String,
    val glyph:       String,
)

private val TYPE_OPTIONS = listOf(
    TypeOption(ChannelType.OPEN,          "OPEN",          "Anyone can read. Posts use a shared gossip key.", "○"),
    TypeOption(ChannelType.CLOSED,        "CLOSED",        "Membership key. Rotation expels members.",       "◆"),
    TypeOption(ChannelType.COMPARTMENTED, "COMPARTMENTED", "Biometric-gated. Physical re-exchange to join.", "◈"),
    TypeOption(ChannelType.ANONYMOUS,     "ANONYMOUS",     "Open read. Author identity is not attributed.",  "◌"),
)

@Composable
fun CreateChannelSheet(
    isCreating: Boolean,
    error:      String?,
    onCreate:   (name: String, type: ChannelType) -> Unit,
    onDismiss:  () -> Unit,
) {
    var name     by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf(ChannelType.OPEN) }

    Column(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg1)
            .padding(16.dp),
    ) {
        // ── Title ─────────────────────────────────────────────────────────
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                "NEW CHANNEL",
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

        Spacer(Modifier.height(16.dp))

        // ── Name field ────────────────────────────────────────────────────
        Text(
            "CHANNEL NAME",
            fontFamily    = MonoFamily,
            fontWeight    = FontWeight.Bold,
            fontSize      = 10.sp,
            color         = Clr.TextMute,
            letterSpacing = 0.08.sp,
        )
        Spacer(Modifier.height(6.dp))
        BasicTextField(
            value         = name,
            onValueChange = { if (it.length <= 48) name = it },
            singleLine    = true,
            modifier      = Modifier
                .fillMaxWidth()
                .background(Clr.Bg3, RoundedCornerShape(6.dp))
                .border(1.dp, Clr.Border, RoundedCornerShape(6.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            textStyle = TextStyle(
                fontFamily = MonoFamily,
                fontSize   = 13.sp,
                color      = Clr.TextPri,
            ),
            cursorBrush = SolidColor(Clr.Green),
            decorationBox = { inner ->
                if (name.isEmpty()) {
                    Text(
                        "e.g. ops-team, announcements…",
                        fontFamily = MonoFamily,
                        fontSize   = 13.sp,
                        color      = Clr.TextMute,
                    )
                }
                inner()
            }
        )

        Spacer(Modifier.height(16.dp))

        // ── Type selector ─────────────────────────────────────────────────
        Text(
            "CHANNEL TYPE",
            fontFamily    = MonoFamily,
            fontWeight    = FontWeight.Bold,
            fontSize      = 10.sp,
            color         = Clr.TextMute,
            letterSpacing = 0.08.sp,
        )
        Spacer(Modifier.height(6.dp))

        TYPE_OPTIONS.forEach { option ->
            val isSelected = selected == option.type
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .background(
                        if (isSelected) Clr.GreenMute else Clr.Bg2,
                        RoundedCornerShape(6.dp),
                    )
                    .border(
                        1.dp,
                        if (isSelected) Clr.GreenDim else Clr.Border,
                        RoundedCornerShape(6.dp),
                    )
                    .clickable { selected = option.type }
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    option.glyph,
                    fontFamily = MonoFamily,
                    fontSize   = 16.sp,
                    color      = if (isSelected) Clr.Green else Clr.TextMute,
                    modifier   = Modifier.width(24.dp),
                )
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        option.label,
                        fontFamily    = MonoFamily,
                        fontWeight    = FontWeight.Bold,
                        fontSize      = 11.sp,
                        color         = if (isSelected) Clr.Green else Clr.TextPri,
                        letterSpacing = 0.06.sp,
                    )
                    Text(
                        option.description,
                        fontFamily = MonoFamily,
                        fontSize   = 9.sp,
                        color      = Clr.TextMute,
                    )
                }
                RadioButton(
                    selected = isSelected,
                    onClick  = { selected = option.type },
                    colors   = RadioButtonDefaults.colors(
                        selectedColor   = Clr.Green,
                        unselectedColor = Clr.TextMute,
                    ),
                )
            }
        }

        if (error != null) {
            Spacer(Modifier.height(8.dp))
            Text(error, fontFamily = MonoFamily, fontSize = 9.sp, color = Clr.Red)
        }

        Spacer(Modifier.height(16.dp))

        // ── Create button ─────────────────────────────────────────────────
        Button(
            onClick  = { if (name.isNotBlank()) onCreate(name.trim(), selected) },
            enabled  = name.isNotBlank() && !isCreating,
            modifier = Modifier.fillMaxWidth(),
            shape    = RoundedCornerShape(6.dp),
            colors   = ButtonDefaults.buttonColors(
                containerColor = Clr.GreenMute,
                contentColor   = Clr.Green,
            ),
        ) {
            if (isCreating) {
                CircularProgressIndicator(Modifier.size(16.dp), color = Clr.Green, strokeWidth = 2.dp)
            } else {
                Text(
                    "CREATE CHANNEL",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 11.sp,
                    letterSpacing = 0.06.sp,
                )
            }
        }
    }
}
