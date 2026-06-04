package mesh.shadowmesh.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

@Composable
fun EmptyState(
    glyph:    String,
    headline: String,
    body:     String,
    modifier: Modifier = Modifier,
    action:   Pair<String, () -> Unit>? = null,
) {
    Column(
        modifier              = modifier
            .fillMaxSize()
            .padding(40.dp),
        horizontalAlignment   = Alignment.CenterHorizontally,
        verticalArrangement   = Arrangement.Center,
    ) {
        Text(
            text       = glyph,
            fontSize   = 48.sp,
            color      = Clr.TextMute,
            fontFamily = MonoFamily,
        )
        Spacer(Modifier.height(20.dp))
        Text(
            text       = headline,
            fontSize   = 13.sp,
            fontFamily = MonoFamily,
            fontWeight = FontWeight.Bold,
            color      = Clr.TextSec,
            textAlign  = TextAlign.Center,
            letterSpacing = 0.08.sp,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text       = body,
            fontSize   = 11.sp,
            fontFamily = MonoFamily,
            color      = Clr.TextMute,
            textAlign  = TextAlign.Center,
            lineHeight = 16.sp,
        )
        if (action != null) {
            Spacer(Modifier.height(24.dp))
            TextButton(onClick = action.second) {
                Text(
                    text       = action.first,
                    fontSize   = 11.sp,
                    fontFamily = MonoFamily,
                    fontWeight = FontWeight.Bold,
                    color      = Clr.Green,
                    letterSpacing = 0.06.sp,
                )
            }
        }
    }
}
