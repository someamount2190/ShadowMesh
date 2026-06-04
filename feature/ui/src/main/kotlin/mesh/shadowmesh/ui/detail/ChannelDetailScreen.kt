package mesh.shadowmesh.ui.detail

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import mesh.shadowmesh.storage.ChannelEntity
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.storage.PostEntity
import mesh.shadowmesh.storage.PostState
import mesh.shadowmesh.ui.components.*
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import java.text.SimpleDateFormat
import java.util.*

// ── Channel detail screen ─────────────────────────────────────────────────────

@Composable
fun ChannelDetailScreen(
    channel:               ChannelEntity,
    posts:                 List<PostEntity>,
    localNodeId:           String,
    onBack:                () -> Unit,
    onPostTap:             (PostEntity) -> Unit,
    onSend:                (String, Boolean) -> Unit,   // (text, burnAfterRead)
    onRetry:               (String) -> Unit,
    onQueueForOnline:      (String) -> Unit    = {},
    onCancelPendingOnline: (String) -> Unit    = {},
    pendingOnlinePostId:   String?             = null,
    onEndorse:             (String) -> Unit    = {},
    onDepart:              () -> Unit          = {},
    onRotateKey:           () -> Unit          = {},
    onViewMembers:         () -> Unit          = {},
    onChannelSettings:     () -> Unit          = {},
    modifier:              Modifier            = Modifier,
) {
    val isComp       = channel.type == ChannelType.COMPARTMENTED
    val isInputLocked = posts.any { it.postState == PostState.PENDING }
    var draft         by remember { mutableStateOf("") }
    var burnToggle    by remember { mutableStateOf(false) }
    var showMenu      by remember { mutableStateOf(false) }
    var compTimer     by remember { mutableStateOf(if (isComp) 30 else 0) }
    var replyTo       by remember { mutableStateOf<PostEntity?>(null) }

    val listState = rememberLazyListState()
    val scope     = rememberCoroutineScope()

    // COMPARTMENTED countdown
    LaunchedEffect(isComp) {
        if (!isComp) return@LaunchedEffect
        while (compTimer > 0) {
            kotlinx.coroutines.delay(1_000)
            compTimer--
        }
    }

    // Auto-scroll to bottom on new posts
    LaunchedEffect(posts.size) {
        if (posts.isNotEmpty()) listState.animateScrollToItem(posts.lastIndex)
    }

    val typeColor = when (channel.type) {
        ChannelType.COMPARTMENTED -> Clr.Green
        ChannelType.CLOSED        -> Clr.GreenDim
        ChannelType.GLOBAL        -> Clr.Amber
        else                      -> Clr.TextSec
    }

    Column(modifier.fillMaxSize().background(Clr.Bg0)) {

        // ── Header ────────────────────────────────────────────────────────────
        Row(
            modifier          = Modifier
                .fillMaxWidth()
                .background(Clr.Bg1)
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(28.dp)) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back",
                    tint = Clr.TextSec, modifier = Modifier.size(16.dp))
            }
            Spacer(Modifier.width(6.dp))
            TypeIcon(channel.type, size = 12)
            Spacer(Modifier.width(6.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(channel.name, color = Clr.TextPri, fontSize = 13.sp,
                        fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
                    Text(channel.type.name, color = typeColor, fontSize = 8.sp,
                        fontFamily = MonoFamily, letterSpacing = 0.08.sp)
                    DhtBars(channel.dhtPopularity)
                }
            }

            // COMP biometric countdown
            if (isComp && compTimer > 0) {
                val timerColor = if (compTimer < 10) Clr.Red else Clr.TextSec
                Text(
                    text     = "🔒${compTimer}s",
                    color    = timerColor,
                    fontSize = 9.sp, fontFamily = MonoFamily, fontWeight = FontWeight.Bold,
                    modifier = Modifier
                        .background(
                            if (compTimer < 10) Clr.RedMute else Clr.Bg3,
                            RoundedCornerShape(3.dp)
                        )
                        .border(1.dp, timerColor.copy(0.5f), RoundedCornerShape(3.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                )
                Spacer(Modifier.width(6.dp))
            }

            Box {
                IconButton(onClick = { showMenu = true }, modifier = Modifier.size(28.dp)) {
                    Icon(Icons.Default.MoreVert, contentDescription = "Menu",
                        tint = Clr.TextSec, modifier = Modifier.size(16.dp))
                }
                DetailMenu(
                    expanded       = showMenu,
                    isClosed       = channel.type == ChannelType.CLOSED,
                    isGlobal       = channel.type == ChannelType.GLOBAL,
                    onDismiss      = { showMenu = false },
                    onDepart       = { showMenu = false; onDepart() },
                    onRotateKey    = { showMenu = false; onRotateKey() },
                    onViewMembers  = { showMenu = false; onViewMembers() },
                    onChannelInfo  = { showMenu = false; onChannelSettings() },
                )
            }
        }
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        // ── Messages ──────────────────────────────────────────────────────────
        val postsById = remember(posts) { posts.associateBy { it.postId } }
        LazyColumn(
            state           = listState,
            modifier        = Modifier.weight(1f),
            contentPadding  = PaddingValues(vertical = 12.dp),
        ) {
            items(posts, key = { it.postId }) { post ->
                val endorsedSource = post.endorsedPostId?.let { postsById[it] }
                MessageBubble(
                    post                = post,
                    isSelf              = post.authorNodeId == localNodeId,
                    onTap               = onPostTap,
                    onRetry             = onRetry,
                    onReply             = { replyTo = post },
                    onQueueForOnline    = onQueueForOnline,
                    pendingOnlinePostId = pendingOnlinePostId,
                    onEndorse           = onEndorse,
                    endorsedSource      = endorsedSource,
                )
            }
        }

        // ── Compose row ───────────────────────────────────────────────────────
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)
        ComposeRow(
            draft               = draft,
            onDraftChange       = { draft = it },
            burnToggle          = burnToggle,
            onBurnToggle        = { burnToggle = !burnToggle },
            isLocked            = isInputLocked,
            replyTo             = replyTo,
            onClearReply        = { replyTo = null },
            pendingOnlinePostId = pendingOnlinePostId,
            onCancelPending     = { pendingOnlinePostId?.let { onCancelPendingOnline(it) } },
            onSend              = {
                if (draft.isNotBlank()) {
                    val sendText = if (replyTo != null)
                        "> [reply:${replyTo!!.postId.take(8)}]\n$draft"
                    else draft
                    onSend(sendText, burnToggle)
                    draft = ""
                    replyTo = null
                    scope.launch { if (posts.isNotEmpty()) listState.animateScrollToItem(posts.lastIndex) }
                }
            }
        )
    }
}

// ── Message bubble ────────────────────────────────────────────────────────────

@Composable
private fun MessageBubble(
    post:               PostEntity,
    isSelf:             Boolean,
    onTap:              (PostEntity) -> Unit,
    onRetry:            (String) -> Unit,
    onReply:            (PostEntity) -> Unit,
    onQueueForOnline:   (String) -> Unit = {},
    pendingOnlinePostId:String?          = null,
    onEndorse:          (String) -> Unit = {},
    endorsedSource:     PostEntity?      = null,
) {
    val isFailed        = post.postState == PostState.FAILED
    val isSyncing       = post.postState == PostState.SYNCING
    val isPending       = post.postState == PostState.PENDING
    val isOfflineLocal  = post.postState == PostState.OFFLINE_LOCAL
    val isPendingOnline = post.postState == PostState.PENDING_ONLINE
    val isPartial       = post.encryptedTier2 == null && post.tier1Unlocked
    val hasFull         = post.encryptedTier2 != null

    Row(
        modifier              = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
        horizontalArrangement = if (isSelf) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            horizontalAlignment = if (isSelf) Alignment.End else Alignment.Start,
            modifier            = Modifier.widthIn(max = 280.dp),
        ) {
            // State tag chips shown above the bubble
            when {
                post.endorsedPostId != null -> {
                    Text(
                        text       = "[ ENDORSED OFFLINE MSG ]",
                        color      = Clr.Green,
                        fontSize   = 7.sp,
                        fontFamily = MonoFamily,
                        modifier   = Modifier
                            .background(Clr.GreenMute, RoundedCornerShape(3.dp))
                            .padding(horizontal = 5.dp, vertical = 2.dp),
                    )
                    Spacer(Modifier.height(4.dp))
                }
                isPendingOnline -> {
                    Text(
                        text       = "[ QUEUED FOR ONLINE ]",
                        color      = Clr.Amber,
                        fontSize   = 7.sp,
                        fontFamily = MonoFamily,
                        modifier   = Modifier
                            .background(Clr.AmberMute, RoundedCornerShape(3.dp))
                            .padding(horizontal = 5.dp, vertical = 2.dp),
                    )
                    Spacer(Modifier.height(4.dp))
                }
                isOfflineLocal -> {
                    Text(
                        text       = "[ OFFLINE THREAD ]",
                        color      = Clr.Amber,
                        fontSize   = 7.sp,
                        fontFamily = MonoFamily,
                        modifier   = Modifier
                            .background(Clr.AmberMute, RoundedCornerShape(3.dp))
                            .padding(horizontal = 5.dp, vertical = 2.dp),
                    )
                    Spacer(Modifier.height(4.dp))
                }
            }

            // Author callsign — only for others
            if (!isSelf) {
                val callsign = "${post.authorNodeId.take(6).uppercase()} (${post.authorNodeId.take(4)}…)"
                Text(callsign, color = Clr.Green, fontSize = 9.sp, fontFamily = MonoFamily,
                    modifier = Modifier.padding(bottom = 3.dp))
            }

            // Bubble
            val isEndorsed  = post.endorsedPostId != null
            val bubbleBg    = when {
                isFailed        -> Clr.RedMute
                isOfflineLocal  -> Clr.Bg2
                isPendingOnline -> Clr.AmberMute
                isEndorsed      -> Clr.GreenMute
                isSelf          -> Clr.SelfBg
                else            -> Clr.Bg3
            }
            val bubbleBord  = when {
                isFailed        -> Clr.Red
                isOfflineLocal  -> Clr.Amber.copy(alpha = 0.4f)
                isPendingOnline -> Clr.Amber
                isEndorsed      -> Clr.GreenDim
                isPending       -> Clr.Amber
                isSelf          -> Clr.SelfBord
                else            -> Clr.Border
            }
            val bubbleShape = if (isSelf)
                RoundedCornerShape(8.dp, 8.dp, 2.dp, 8.dp)
            else
                RoundedCornerShape(8.dp, 8.dp, 8.dp, 2.dp)

            Box(
                modifier = Modifier
                    .background(bubbleBg, bubbleShape)
                    .border(1.dp, bubbleBord, bubbleShape)
                    .clip(bubbleShape)
                    .clickable { onTap(post) }
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                // Burn-after-read corner badge
                if (post.burnAfterRead) {
                    Text("🔥", fontSize = 8.sp,
                        modifier = Modifier.align(Alignment.TopEnd))
                }

                when {
                    isFailed        -> FailedContent(onRetry = { onRetry(post.postId) })
                    isSyncing       -> Text("⟳ In mesh…", color = Clr.TextMute, fontSize = 11.sp,
                                        fontStyle = FontStyle.Italic, fontFamily = MonoFamily)
                    isPending       -> Text("⟳ Sending…", color = Clr.Amber, fontSize = 11.sp,
                                        fontStyle = FontStyle.Italic, fontFamily = MonoFamily)
                    isPendingOnline -> Text("⟳ Queued for online…", color = Clr.Amber, fontSize = 11.sp,
                                        fontStyle = FontStyle.Italic, fontFamily = MonoFamily)
                    post.endorsedPostId != null -> EndorsedContent(source = endorsedSource)
                    isOfflineLocal  -> FullContent(post)
                    isPartial       -> PartialContent()
                    hasFull         -> FullContent(post)
                    else            -> Text("Assembling…", color = Clr.TextMute, fontSize = 11.sp,
                                        fontStyle = FontStyle.Italic)
                }
            }

            // Fragment progress bar (visible while assembling)
            val showProgress = post.fragmentsTotal > 0 &&
                post.fragmentsReceived < post.fragmentsTotal &&
                post.postState != PostState.CONFIRMED &&
                !isOfflineLocal && !isPendingOnline
            if (showProgress) {
                Spacer(Modifier.height(4.dp))
                val progress = post.fragmentsReceived.toFloat() / post.fragmentsTotal.toFloat()
                LinearProgressIndicator(
                    progress     = { progress },
                    modifier     = Modifier.fillMaxWidth().height(2.dp),
                    color        = Clr.Green,
                    trackColor   = Clr.Bg4,
                )
                Text(
                    "${post.fragmentsReceived}/${post.fragmentsTotal} fragments",
                    color    = Clr.TextMute,
                    fontSize = 8.sp,
                    fontFamily = MonoFamily,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }

            // Footer: time + state + reply + "queue online" for own offline messages
            Spacer(Modifier.height(3.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(5.dp),
                verticalAlignment     = Alignment.CenterVertically,
                modifier              = Modifier.padding(horizontal = 4.dp),
            ) {
                Text(fmtTime(post.createdAtMs), color = Clr.TextMute,
                    fontSize = 8.sp, fontFamily = MonoFamily)
                PostStateBadge(post.postState)
                if (post.postState == PostState.CONFIRMED && post.fragmentsTotal > 0) {
                    Text("${post.fragmentsReceived}/${post.fragmentsTotal}f",
                        color = Clr.TextMute, fontSize = 8.sp, fontFamily = MonoFamily)
                }
                Spacer(Modifier.weight(1f))
                // "→ online" — own OFFLINE_LOCAL only, when no post is already queued
                if (isSelf && isOfflineLocal && pendingOnlinePostId == null) {
                    Text(
                        "→ online",
                        color      = Clr.Amber,
                        fontSize   = 8.sp,
                        fontFamily = MonoFamily,
                        modifier   = Modifier
                            .border(1.dp, Clr.Amber.copy(alpha = 0.5f), RoundedCornerShape(3.dp))
                            .clickable { onQueueForOnline(post.postId) }
                            .padding(horizontal = 5.dp, vertical = 2.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                }
                // "✦ endorse" — any OFFLINE_LOCAL message (own or peer's)
                if (isOfflineLocal) {
                    Text(
                        "✦ endorse",
                        color      = Clr.GreenDim,
                        fontSize   = 8.sp,
                        fontFamily = MonoFamily,
                        modifier   = Modifier
                            .border(1.dp, Clr.GreenDim.copy(alpha = 0.5f), RoundedCornerShape(3.dp))
                            .clickable { onEndorse(post.postId) }
                            .padding(horizontal = 5.dp, vertical = 2.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                }
                // Reply button
                Text(
                    "↩",
                    color    = Clr.TextMute,
                    fontSize = 10.sp,
                    modifier = Modifier
                        .clickable { onReply(post) }
                        .padding(horizontal = 4.dp, vertical = 2.dp),
                )
            }
        }
    }
}

@Composable
private fun FullContent(post: PostEntity) {
    Text(
        text       = "(tap to read full message)",
        color      = Clr.TextSec,
        fontSize   = 12.sp,
        lineHeight = 18.sp,
        fontFamily = MonoFamily,
        fontStyle  = FontStyle.Italic,
    )
}

/**
 * Bubble body for endorsed posts. Shows the endorsement header and, when the
 * original offline post is still in the local DB, a condensed quote of its metadata.
 */
@Composable
private fun EndorsedContent(source: PostEntity?) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        // Endorsement header chip
        Text(
            text       = "✦  ENDORSED OFFLINE MSG",
            color      = Clr.Green,
            fontSize   = 9.sp,
            fontFamily = MonoFamily,
            fontWeight = FontWeight.Bold,
        )
        HorizontalDivider(color = Clr.GreenDim.copy(alpha = 0.4f), thickness = 1.dp)
        if (source != null) {
            // Show original author + timestamp from the local offline post
            val callsign = source.authorNodeId.take(8).uppercase()
            val time     = fmtTime(source.createdAtMs)
            Text(
                "From : $callsign",
                color = Clr.TextSec, fontSize = 9.sp, fontFamily = MonoFamily,
            )
            Text(
                "At   : $time",
                color = Clr.TextSec, fontSize = 9.sp, fontFamily = MonoFamily,
            )
            HorizontalDivider(color = Clr.Border, thickness = 1.dp)
        }
        Text(
            text       = "(tap to read endorsed content)",
            color      = Clr.TextMute,
            fontSize   = 11.sp,
            lineHeight = 17.sp,
            fontFamily = MonoFamily,
            fontStyle  = FontStyle.Italic,
        )
    }
}

@Composable
private fun PartialContent() {
    Column {
        Text("▪▪▪", color = Clr.TextMute, fontSize = 12.sp, fontFamily = MonoFamily,
            letterSpacing = 0.2.sp)
        Text("Loading…", color = Clr.TextMute, fontSize = 9.sp, fontFamily = MonoFamily,
            modifier = Modifier.padding(top = 2.dp))
    }
}

@Composable
private fun FailedContent(onRetry: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("No relay reached", color = Clr.Red, fontSize = 11.sp, fontFamily = MonoFamily)
        Box(
            Modifier
                .clip(RoundedCornerShape(3.dp))
                .border(1.dp, Clr.Red, RoundedCornerShape(3.dp))
                .clickable(onClick = onRetry)
                .padding(horizontal = 8.dp, vertical = 2.dp)
        ) {
            Text("Retry", color = Clr.Red, fontSize = 9.sp, fontFamily = MonoFamily)
        }
    }
}

// ── Compose row ───────────────────────────────────────────────────────────────

@Composable
private fun ComposeRow(
    draft:               String,
    onDraftChange:       (String) -> Unit,
    burnToggle:          Boolean,
    onBurnToggle:        () -> Unit,
    isLocked:            Boolean,
    replyTo:             PostEntity?,
    onClearReply:        () -> Unit,
    onSend:              () -> Unit,
    pendingOnlinePostId: String?    = null,
    onCancelPending:     () -> Unit = {},
) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg1)
            .padding(12.dp)
    ) {
        // Pending online banner — shown when a message is queued for online submission
        if (pendingOnlinePostId != null) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(Clr.AmberMute, RoundedCornerShape(4.dp))
                    .border(1.dp, Clr.Amber, RoundedCornerShape(4.dp))
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "[ PENDING ONLINE ] 1 message queued",
                    color      = Clr.Amber,
                    fontSize   = 9.sp,
                    fontFamily = MonoFamily,
                    modifier   = Modifier.weight(1f),
                )
                Text(
                    "Cancel",
                    color    = Clr.Amber,
                    fontSize = 9.sp,
                    fontFamily = MonoFamily,
                    modifier = Modifier
                        .border(1.dp, Clr.Amber, RoundedCornerShape(3.dp))
                        .clickable(onClick = onCancelPending)
                        .padding(horizontal = 8.dp, vertical = 2.dp),
                )
            }
            Spacer(Modifier.height(8.dp))
        }

        // Reply-to strip
        if (replyTo != null) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(Clr.Bg3, RoundedCornerShape(4.dp))
                    .border(1.dp, Clr.GreenDim, RoundedCornerShape(4.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "↩ Replying to ${replyTo.authorNodeId.take(6).uppercase()}",
                    fontFamily = MonoFamily,
                    fontSize   = 9.sp,
                    color      = Clr.GreenDim,
                    modifier   = Modifier.weight(1f),
                )
                Text(
                    "✕",
                    fontFamily = MonoFamily,
                    fontSize   = 10.sp,
                    color      = Clr.TextMute,
                    modifier   = Modifier.clickable(onClick = onClearReply).padding(4.dp),
                )
            }
            Spacer(Modifier.height(6.dp))
        }

        if (isLocked) {
            Text(
                "⟳ Waiting for relay contact…",
                color    = Clr.Amber,
                fontSize = 9.sp, fontFamily = MonoFamily,
                modifier = Modifier.align(Alignment.CenterHorizontally).padding(bottom = 6.dp),
            )
        }

        Row(
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            // Burn toggle
            Box(
                Modifier
                    .size(36.dp)
                    .background(
                        if (burnToggle) Clr.AmberMute else Color.Transparent,
                        RoundedCornerShape(4.dp)
                    )
                    .border(1.dp,
                        if (burnToggle) Clr.Amber else Clr.Border,
                        RoundedCornerShape(4.dp))
                    .clickable(onClick = onBurnToggle),
                contentAlignment = Alignment.Center,
            ) {
                Text("🔥", fontSize = 14.sp)
            }

            // Text field
            BasicTextField(
                value         = draft,
                onValueChange = onDraftChange,
                enabled       = !isLocked,
                textStyle     = TextStyle(
                    color      = Clr.TextPri,
                    fontSize   = 12.sp,
                    fontFamily = MonoFamily,
                    lineHeight = 17.sp,
                ),
                cursorBrush   = SolidColor(Clr.Green),
                decorationBox = { inner ->
                    Box(
                        Modifier
                            .weight(1f)
                            .background(
                                if (isLocked) Clr.Bg1 else Clr.Bg2,
                                RoundedCornerShape(4.dp)
                            )
                            .border(1.dp, Clr.Border, RoundedCornerShape(4.dp))
                            .padding(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        if (draft.isEmpty()) {
                            Text("Type a message…", color = Clr.TextMute,
                                fontSize = 12.sp, fontFamily = MonoFamily)
                        }
                        inner()
                    }
                },
                modifier = Modifier.weight(1f),
            )

            // Send
            val canSend = !isLocked && draft.isNotBlank()
            Box(
                Modifier
                    .size(36.dp)
                    .background(
                        if (canSend) Clr.Green else Clr.Bg3,
                        RoundedCornerShape(4.dp)
                    )
                    .clickable(enabled = canSend, onClick = onSend),
                contentAlignment = Alignment.Center,
            ) {
                Text("↑", color = if (canSend) Color.Black else Clr.TextMute,
                    fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

// ── Actions menu ──────────────────────────────────────────────────────────────

@Composable
private fun DetailMenu(
    expanded:      Boolean,
    isClosed:      Boolean,
    isGlobal:      Boolean = false,
    onDismiss:     () -> Unit,
    onDepart:      () -> Unit,
    onRotateKey:   () -> Unit,
    onViewMembers: () -> Unit,
    onChannelInfo: () -> Unit,
) {
    DropdownMenu(
        expanded         = expanded,
        onDismissRequest = onDismiss,
    ) {
        DropdownMenuItem(
            text    = { Text("Channel settings", color = Clr.TextSec, fontSize = 11.sp, fontFamily = MonoFamily) },
            onClick = onChannelInfo,
        )
        DropdownMenuItem(
            text    = { Text("View members", color = Clr.TextSec, fontSize = 11.sp, fontFamily = MonoFamily) },
            onClick = onViewMembers,
        )
        if (isClosed) {
            DropdownMenuItem(
                text    = { Text("Rotate key", color = Clr.Amber, fontSize = 11.sp, fontFamily = MonoFamily) },
                onClick = onRotateKey,
            )
        }
        if (!isGlobal) {
            HorizontalDivider(color = Clr.Border, thickness = 1.dp)
            DropdownMenuItem(
                text    = { Text("Depart channel", color = Clr.Red, fontSize = 11.sp, fontFamily = MonoFamily) },
                onClick = onDepart,
            )
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

private fun fmtTime(ms: Long): String {
    return SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ms))
}
