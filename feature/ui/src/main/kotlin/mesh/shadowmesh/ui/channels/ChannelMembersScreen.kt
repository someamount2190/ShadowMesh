package mesh.shadowmesh.ui.channels

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.ui.components.EmptyState
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import mesh.shadowmesh.ui.viewmodel.ContactItem

@Composable
fun ChannelMembersScreen(
    channelName: String,
    members:     List<ContactItem>,
    onBack:      () -> Unit,
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
            Column(Modifier.weight(1f)) {
                Text(
                    "MEMBERS",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 13.sp,
                    color         = Clr.TextPri,
                    letterSpacing = 0.1.sp,
                )
                Text(
                    channelName,
                    fontFamily = MonoFamily,
                    fontSize   = 10.sp,
                    color      = Clr.TextMute,
                )
            }
            Text(
                "${members.size}",
                fontFamily = MonoFamily,
                fontSize   = 10.sp,
                color      = Clr.TextMute,
            )
        }

        if (members.isEmpty()) {
            EmptyState(
                glyph    = "◎",
                headline = "NO KNOWN MEMBERS",
                body     = "Members appear here once they exchange keys\nand are reachable on the mesh.",
            )
        } else {
            LazyColumn(
                contentPadding = PaddingValues(vertical = 8.dp, horizontal = 12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(members, key = { it.nodeId }) { member ->
                    MemberRow(member)
                }
            }
        }
    }
}

@Composable
private fun MemberRow(member: ContactItem) {
    val trustColor = when (member.trustLabel) {
        "PHYSICAL"   -> Clr.Green
        "INTRODUCED" -> Clr.Amber
        else         -> Clr.TextMute
    }
    Row(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg2, RoundedCornerShape(6.dp))
            .border(1.dp, Clr.Border, RoundedCornerShape(6.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(6.dp)
                .background(
                    if (member.isReachable) Clr.Green else Clr.TextMute,
                    RoundedCornerShape(3.dp),
                )
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                member.displayId,
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 11.sp,
                color         = Clr.TextPri,
                letterSpacing = 0.04.sp,
            )
        }
        Text(
            member.trustLabel,
            fontFamily = MonoFamily,
            fontSize   = 9.sp,
            color      = trustColor,
            letterSpacing = 0.06.sp,
        )
    }
}
