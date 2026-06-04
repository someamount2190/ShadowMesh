@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package mesh.shadowmesh.ui.channels

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.storage.ChannelEntity
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.ui.components.*
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import mesh.shadowmesh.ui.viewmodel.ChannelListItem
import mesh.shadowmesh.ui.viewmodel.ForumUiViewModel

// ── Channel list screen ───────────────────────────────────────────────────────

@Composable
fun ChannelListScreen(
    items:          List<ChannelListItem>,
    networkMode:    NetworkMode,
    meshLiveness:   MeshLiveness,
    isCreating:     Boolean,
    createError:    String?,
    onChannelClick: (ChannelEntity) -> Unit,
    onCreateChannel:(String, mesh.shadowmesh.storage.ChannelType) -> Unit,
    onClearError:   () -> Unit,
    onSettingsClick:() -> Unit,
    onChipClick:    () -> Unit,
    modifier:       Modifier = Modifier,
) {
    var showCreateSheet by remember { mutableStateOf(false) }

    Box(modifier.fillMaxSize().background(Clr.Bg0)) {
        Column(Modifier.fillMaxSize()) {
            // ── Status bar ────────────────────────────────────────────────────
            ChannelListHeader(
                networkMode    = networkMode,
                meshLiveness   = meshLiveness,
                onChipClick    = onChipClick,
                onSettingsClick= onSettingsClick,
            )
            HorizontalDivider(color = Clr.Border, thickness = 1.dp)

            val channelItems = items.filterIsInstance<ChannelListItem.Channel>()
            if (channelItems.isEmpty()) {
                EmptyState(
                    glyph    = "◈",
                    headline = "NO CHANNELS YET",
                    body     = "Create a channel to start posting,\nor wait to receive one from a contact.",
                    action   = "CREATE CHANNEL" to { showCreateSheet = true },
                )
            } else {
                // ── Channel list ──────────────────────────────────────────────
                LazyColumn(
                    modifier            = Modifier.weight(1f),
                    contentPadding      = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    items(items, key = { when(it) {
                        is ChannelListItem.SectionHeader -> "hdr_${it.label}"
                        is ChannelListItem.Channel       -> it.entity.channelId
                    }}) { item ->
                        when (item) {
                            is ChannelListItem.SectionHeader ->
                                SectionLabel(item.label, Modifier.padding(top = 4.dp))
                            is ChannelListItem.Channel ->
                                ChannelRow(item.entity, item.unread, onChannelClick)
                        }
                    }
                }
            }
        }

        // ── FAB ───────────────────────────────────────────────────────────────
        if (items.filterIsInstance<ChannelListItem.Channel>().isNotEmpty()) {
            FloatingActionButton(
                onClick          = { showCreateSheet = true },
                containerColor   = Clr.GreenMute,
                contentColor     = Clr.Green,
                shape            = CircleShape,
                modifier         = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 16.dp, bottom = 16.dp),
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add")
            }
        }
    }

    // ── Create channel bottom sheet ───────────────────────────────────────────
    if (showCreateSheet) {
        ModalBottomSheet(
            onDismissRequest = { showCreateSheet = false; onClearError() },
            containerColor   = Clr.Bg1,
        ) {
            CreateChannelSheet(
                isCreating = isCreating,
                error      = createError,
                onCreate   = { name, type ->
                    onCreateChannel(name, type)
                    if (createError == null) showCreateSheet = false
                },
                onDismiss  = { showCreateSheet = false; onClearError() },
            )
        }
    }
}

// ── Header ────────────────────────────────────────────────────────────────────

@Composable
private fun ChannelListHeader(
    networkMode:     NetworkMode,
    meshLiveness:    MeshLiveness,
    onChipClick:     () -> Unit,
    onSettingsClick: () -> Unit,
) {
    Row(
        modifier          = Modifier
            .fillMaxWidth()
            .background(Clr.Bg1)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Liveness dot + wordmark
        LiveDot(meshLiveness)
        Spacer(Modifier.width(8.dp))
        Text(
            text          = "SHADOWMESH",
            color         = Clr.Green,
            fontSize      = 12.sp,
            fontWeight    = FontWeight.Bold,
            fontFamily    = MonoFamily,
            letterSpacing = 0.12.sp,
        )

        Spacer(Modifier.weight(1f))

        // Network mode chip — tappable for info sheet
        if (networkMode != NetworkMode.HEALTHY) {
            Box(Modifier.clickable(onClick = onChipClick)) {
                NetworkChip(networkMode)
            }
            Spacer(Modifier.width(8.dp))
        }

        // Settings
        IconButton(onClick = onSettingsClick, modifier = Modifier.size(28.dp)) {
            Icon(Icons.Default.Settings, contentDescription = "Settings",
                tint = Clr.TextSec, modifier = Modifier.size(16.dp))
        }
    }
}

// ── Channel row ───────────────────────────────────────────────────────────────

@Composable
private fun ChannelRow(
    channel:  ChannelEntity,
    unread:   Int,
    onClick:  (ChannelEntity) -> Unit,
) {
    val isPrivate = channel.type == ChannelType.COMPARTMENTED || channel.type == ChannelType.CLOSED
    val isComp    = channel.type == ChannelType.COMPARTMENTED
    val isGlobal  = channel.type == ChannelType.GLOBAL
    val railColor = when (channel.type) {
        ChannelType.COMPARTMENTED -> Clr.Green
        ChannelType.CLOSED        -> Clr.GreenDim
        ChannelType.GLOBAL        -> Clr.Amber
        else                      -> Color.Transparent
    }

    // hovered was wired to animateColorAsState but was never set to true —
    // no pointerInput or hoverable modifier existed, so the animation never fired.
    // Removed; Modifier.clickable already provides a ripple press indication for free.
    val bgColor = Clr.Bg2

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .clickable { onClick(channel) }
            .height(IntrinsicSize.Min),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Left colour rail — COMPARTMENTED/CLOSED only
        Box(
            Modifier
                .width(3.dp)
                .fillMaxHeight()
                .background(railColor, RoundedCornerShape(topStart = 2.dp, bottomStart = 2.dp))
        )

        Row(
            modifier          = Modifier
                .weight(1f)
                .background(bgColor)
                .border(1.dp, Clr.Border, RoundedCornerShape(topEnd = 4.dp, bottomEnd = 4.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TypeIcon(channel.type, size = 13)

            Column(Modifier.weight(1f)) {
                // Name + COMP badge
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text         = channel.name,
                        color        = Clr.TextPri,
                        fontSize     = 12.sp,
                        fontWeight   = FontWeight.SemiBold,
                        fontFamily   = MonoFamily,
                        maxLines     = 1,
                    )
                    if (isComp) {
                        CompBadge()
                    }
                    if (isGlobal) {
                        GlobalBadge()
                    }
                }

                Spacer(Modifier.height(3.dp))

                // DHT bars + percentage + recency
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    DhtBars(channel.dhtPopularity)
                    Text(
                        "${channel.dhtPopularity}% DHT",
                        color    = Clr.TextMute,
                        fontSize = 9.sp,
                        fontFamily = MonoFamily,
                    )
                    Text("·", color = Clr.TextMute, fontSize = 9.sp)
                    Text(
                        relTime(channel.lastActivityMs),
                        color    = Clr.TextMute,
                        fontSize = 9.sp,
                        fontFamily = MonoFamily,
                    )
                }
            }

            // Unread badge
            if (unread > 0) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .defaultMinSize(minWidth = 18.dp, minHeight = 18.dp)
                        .background(Clr.Red, CircleShape)
                        .padding(horizontal = 4.dp),
                ) {
                    Text(
                        text       = if (unread > 99) "99+" else unread.toString(),
                        color      = Color.Black,
                        fontSize   = 9.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = MonoFamily,
                    )
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

@Composable
private fun CompBadge() {
    Text(
        text          = "COMP",
        color         = Clr.Green,
        fontSize      = 8.sp,
        fontWeight    = FontWeight.Bold,
        fontFamily    = MonoFamily,
        letterSpacing = 0.06.sp,
        modifier      = Modifier
            .background(Clr.GreenMute, RoundedCornerShape(2.dp))
            .border(1.dp, Clr.Green.copy(0.3f), RoundedCornerShape(2.dp))
            .padding(horizontal = 4.dp, vertical = 1.dp),
    )
}

@Composable
private fun GlobalBadge() {
    Text(
        text          = "GLOBAL",
        color         = Clr.Amber,
        fontSize      = 8.sp,
        fontWeight    = FontWeight.Bold,
        fontFamily    = MonoFamily,
        letterSpacing = 0.06.sp,
        modifier      = Modifier
            .background(Clr.AmberMute, RoundedCornerShape(2.dp))
            .border(1.dp, Clr.Amber.copy(0.3f), RoundedCornerShape(2.dp))
            .padding(horizontal = 4.dp, vertical = 1.dp),
    )
}

private fun relTime(ms: Long): String {
    val d = System.currentTimeMillis() - ms
    return when {
        d < 60_000L       -> "${d / 1_000}s ago"
        d < 3_600_000L    -> "${d / 60_000}m ago"
        d < 86_400_000L   -> "${d / 3_600_000}h ago"
        else              -> "${d / 86_400_000}d ago"
    }
}
