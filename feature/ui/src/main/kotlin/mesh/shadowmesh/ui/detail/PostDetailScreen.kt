package mesh.shadowmesh.ui.detail

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.storage.ChannelEntity
import mesh.shadowmesh.storage.PostEntity
import mesh.shadowmesh.storage.ReputationTier
import mesh.shadowmesh.ui.components.RepBadge
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun PostDetailScreen(
    post:          PostEntity,
    channel:       ChannelEntity,
    displayText:   String,
    repTier:       ReputationTier?,
    showReputation:Boolean,
    poll:          PollUiState?,
    onBack:        () -> Unit,
    onVote:        (Int) -> Unit,
    modifier:      Modifier = Modifier,
) {
    val callsign = if (post.authorNodeId == "self") "You"
    else "${post.authorNodeId.take(6).uppercase()} (${post.authorNodeId.take(4)}…)"

    Column(modifier.fillMaxSize().background(Clr.Bg0)) {
        // Header
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
            Text(channel.name, color = Clr.TextSec, fontSize = 11.sp, fontFamily = MonoFamily)
        }
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Author + time
            Row(
                modifier              = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.Top,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(callsign, color = Clr.Green, fontSize = 11.sp,
                        fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
                    if (repTier != null) RepBadge(repTier)
                }
                Text(fmtTime(post.createdAtMs), color = Clr.TextMute,
                    fontSize = 10.sp, fontFamily = MonoFamily)
            }

            HorizontalDivider(color = Clr.Border)

            // Full content
            Text(displayText, color = Clr.TextPri, fontSize = 13.sp,
                lineHeight = 20.sp, fontFamily = MonoFamily)

            // Delivery line
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("✓✓", color = Clr.Green, fontSize = 11.sp, fontFamily = MonoFamily)
                Text(
                    "Delivered · ${post.fragmentsReceived} fragments",
                    color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily,
                )
            }

            // Reputation warning
            if (showReputation && repTier != null) {
                WarningBox(
                    header  = "⚠ REPUTATION: ${repTier.name}",
                    body    = "Reputation scores are local estimates only. " +
                              "Do not rely on reputation for operational security decisions.",
                    color   = Clr.Amber,
                    bgColor = Clr.AmberMute,
                )
            }

            HorizontalDivider(color = Clr.Border)

            // Poll
            if (poll != null) {
                PollSection(poll, onVote)
            }
        }
    }
}

// ── Poll section ──────────────────────────────────────────────────────────────

data class PollUiState(
    val question: String,
    val options:  List<String>,
    val votes:    List<Int>,
    val total:    Int,
    val myVote:   Int,   // -1 = not voted
)

@Composable
private fun PollSection(poll: PollUiState, onVote: (Int) -> Unit) {
    var localVote by remember { mutableStateOf(poll.myVote) }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text          = "📊 POLL: ${poll.question}",
            color         = Clr.Amber,
            fontSize      = 10.sp,
            fontWeight    = FontWeight.Bold,
            fontFamily    = MonoFamily,
            letterSpacing = 0.08.sp,
        )
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        poll.options.forEachIndexed { i, option ->
            val pct    = if (poll.total > 0) (poll.votes.getOrElse(i){0} * 100f / poll.total) else 0f
            val isWin  = poll.votes.getOrElse(i){0} == (poll.votes.maxOrNull() ?: 0) && poll.total > 0
            val isVote = localVote == i

            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Row(
                    modifier              = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(option, color = if (isVote) Clr.Green else Clr.TextPri,
                        fontSize = 11.sp, fontFamily = MonoFamily)
                    Text("${pct.toInt()}%", color = Clr.TextMute,
                        fontSize = 10.sp, fontFamily = MonoFamily)
                }
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .background(Clr.Bg4, RoundedCornerShape(3.dp))
                ) {
                    Box(
                        Modifier
                            .fillMaxWidth(pct / 100f)
                            .fillMaxHeight()
                            .background(
                                if (isWin) Clr.Green else Clr.GreenDim,
                                RoundedCornerShape(3.dp)
                            )
                    )
                }
            }
        }

        Text(
            "${poll.total} voters total",
            color    = Clr.TextMute, fontSize = 9.sp,
            fontFamily = MonoFamily,
            modifier = Modifier.align(Alignment.End),
        )

        // Vote buttons
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            poll.options.forEachIndexed { i, option ->
                val selected = localVote == i
                Box(
                    Modifier
                        .background(
                            if (selected) Clr.GreenMute else Clr.Bg3,
                            RoundedCornerShape(3.dp)
                        )
                        .border(
                            1.dp,
                            if (selected) Clr.Green else Clr.Border,
                            RoundedCornerShape(3.dp)
                        )
                        .clip(RoundedCornerShape(3.dp))
                        .clickable { localVote = i; onVote(i) }
                        .padding(horizontal = 10.dp, vertical = 5.dp),
                ) {
                    Text("Vote: $option",
                        color    = if (selected) Clr.Green else Clr.TextSec,
                        fontSize = 10.sp, fontFamily = MonoFamily)
                }
            }
        }

        WarningBox(
            header  = "⚠ Poll results are peer-reported and unverifiable.",
            body    = "Treat as indicative only.",
            color   = Clr.Amber,
            bgColor = Clr.AmberMute,
        )
    }
}

// ── Warning box ───────────────────────────────────────────────────────────────

@Composable
private fun WarningBox(header: String, body: String, color: Color, bgColor: Color) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(bgColor, RoundedCornerShape(4.dp))
            .border(1.dp, color.copy(0.3f), RoundedCornerShape(4.dp))
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        Text(header, color = color, fontSize = 9.sp,
            fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
        Text(body, color = Clr.TextSec, fontSize = 9.sp,
            lineHeight = 14.sp, fontFamily = MonoFamily)
    }
}

private fun fmtTime(ms: Long): String =
    SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ms))
