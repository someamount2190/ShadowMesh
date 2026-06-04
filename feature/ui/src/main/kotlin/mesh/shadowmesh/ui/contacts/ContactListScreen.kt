package mesh.shadowmesh.ui.contacts

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.ui.components.EmptyState
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import mesh.shadowmesh.ui.viewmodel.ContactItem

@Composable
fun ContactListScreen(
    contacts:       List<ContactItem>,
    onAddContact:   () -> Unit,
    onBack:         () -> Unit,
) {
    Box(
        Modifier
            .fillMaxSize()
            .background(Clr.Bg0)
    ) {
        Column(Modifier.fillMaxSize()) {
            // ── Header ────────────────────────────────────────────────────
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
                    "CONTACTS",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 13.sp,
                    color         = Clr.TextPri,
                    letterSpacing = 0.1.sp,
                    modifier      = Modifier.weight(1f),
                )
                Text(
                    "${contacts.size} peers",
                    fontFamily = MonoFamily,
                    fontSize   = 10.sp,
                    color      = Clr.TextMute,
                )
            }

            // ── List ──────────────────────────────────────────────────────
            if (contacts.isEmpty()) {
                EmptyState(
                    glyph    = "◎",
                    headline = "NO CONTACTS YET",
                    body     = "Add a contact by sharing your node code\nvia NFC tap or QR scan.",
                    action   = "ADD FIRST CONTACT" to onAddContact,
                )
            } else {
                LazyColumn(
                    Modifier.weight(1f),
                    contentPadding = PaddingValues(vertical = 8.dp),
                ) {
                    items(contacts, key = { it.nodeId }) { contact ->
                        ContactRow(contact)
                    }
                }
            }
        }

        // ── FAB ───────────────────────────────────────────────────────────
        if (contacts.isNotEmpty()) {
            FloatingActionButton(
                onClick          = onAddContact,
                modifier         = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(20.dp),
                containerColor   = Clr.GreenMute,
                contentColor     = Clr.Green,
                shape            = RoundedCornerShape(12.dp),
            ) {
                Icon(Icons.Default.Add, "Add contact", tint = Clr.Green)
            }
        }
    }
}

@Composable
private fun ContactRow(contact: ContactItem) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .background(Clr.Bg2, RoundedCornerShape(6.dp))
            .border(1.dp, Clr.Border, RoundedCornerShape(6.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Trust colour strip
        val trustColor = when (contact.trustLabel) {
            "PHYSICAL"   -> Clr.Green
            "INTRODUCED" -> Clr.Amber
            else         -> Clr.TextMute
        }
        Box(
            Modifier
                .width(3.dp)
                .height(32.dp)
                .background(trustColor, RoundedCornerShape(2.dp))
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                contact.displayId,
                fontFamily    = MonoFamily,
                fontSize      = 11.sp,
                fontWeight    = FontWeight.Bold,
                color         = Clr.TextPri,
                letterSpacing = 0.04.sp,
            )
            Text(
                contact.trustLabel,
                fontFamily = MonoFamily,
                fontSize   = 9.sp,
                color      = trustColor,
                letterSpacing = 0.06.sp,
            )
        }
        // Reachability dot
        Box(
            Modifier
                .size(8.dp)
                .background(
                    if (contact.isReachable) Clr.Green else Clr.TextMute,
                    RoundedCornerShape(4.dp),
                )
        )
    }
}
