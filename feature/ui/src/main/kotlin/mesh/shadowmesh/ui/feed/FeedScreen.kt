package mesh.shadowmesh.ui.feed

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.storage.ChannelEntity
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.storage.PostState
import mesh.shadowmesh.ui.components.EmptyState
import mesh.shadowmesh.ui.components.TypeIcon
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import mesh.shadowmesh.ui.viewmodel.FeedItem
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun FeedScreen(
    items:          List<FeedItem>,
    onItemClick:    (ChannelEntity) -> Unit,
    modifier:       Modifier = Modifier,
) {
    Column(modifier.fillMaxSize().background(Clr.Bg0)) {
        // Header
        Box(
            Modifier
                .fillMaxWidth()
                .background(Clr.Bg1)
                .padding(horizontal = 14.dp, vertical = 10.dp)
        ) {
            Text("Feed", color = Clr.TextPri, fontSize = 13.sp,
                fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
        }
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        if (items.isEmpty()) {
            EmptyState(
                glyph    = "◌",
                headline = "FEED IS EMPTY",
                body     = "Confirmed posts from all your channels\nappear here once they arrive.",
            )
        } else {
            LazyColumn(
                modifier       = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(items, key = { it.post.postId }) { item ->
                    FeedRow(item, onClick = { onItemClick(item.channel) })
                }
            }
        }
    }
}

@Composable
private fun FeedRow(item: FeedItem, onClick: () -> Unit) {
    val post    = item.post
    val channel = item.channel
    val isPrivate = channel.type == ChannelType.COMPARTMENTED || channel.type == ChannelType.CLOSED
    val railColor = when (channel.type) {
        ChannelType.COMPARTMENTED -> Clr.Green
        ChannelType.CLOSED        -> Clr.GreenDim
        ChannelType.GLOBAL        -> Clr.Amber
        else                      -> Clr.Border
    }
    val isSyncing = post.postState == PostState.SYNCING

    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .clickable(onClick = onClick)
            .height(IntrinsicSize.Min)
    ) {
        // Left tier rail
        Box(
            Modifier
                .width(3.dp)
                .fillMaxHeight()
                .background(railColor)
        )
        Column(
            Modifier
                .weight(1f)
                .background(Clr.Bg2)
                .border(1.dp, Clr.Border,
                    RoundedCornerShape(topEnd = 4.dp, bottomEnd = 4.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            // Channel + time
            Row(
                modifier              = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    TypeIcon(channel.type, size = 11)
                    Text(channel.name, color = Clr.TextSec,
                        fontSize = 10.sp, fontFamily = MonoFamily)
                }
                Text(fmtTime(post.createdAtMs), color = Clr.TextMute,
                    fontSize = 9.sp, fontFamily = MonoFamily)
            }

            Spacer(Modifier.height(4.dp))

            // Author callsign
            val callsign = if (post.authorNodeId == "self") "You"
            else "${post.authorNodeId.take(6).uppercase()} (${post.authorNodeId.take(4)}…)"
            Text("▸ $callsign", color = Clr.Green, fontSize = 10.sp, fontFamily = MonoFamily)

            Spacer(Modifier.height(3.dp))

            // Preview
            val preview = when {
                post.burnAfterRead               -> "🔥 Burn-after-read message"
                isSyncing                        -> "⟳ In mesh…"
                post.encryptedTier2 != null      -> "(decrypted at open)"
                post.tier1Unlocked               -> "▪▪▪"
                else                             -> "Assembling…"
            }
            Text(
                text       = preview,
                color      = if (isSyncing) Clr.TextMute else Clr.TextPri,
                fontSize   = 11.sp,
                lineHeight = 15.sp,
                fontStyle  = if (isSyncing) FontStyle.Italic else FontStyle.Normal,
                fontFamily = MonoFamily,
                maxLines   = 2,
            )
        }
    }
}

private fun fmtTime(ms: Long): String =
    SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ms))
