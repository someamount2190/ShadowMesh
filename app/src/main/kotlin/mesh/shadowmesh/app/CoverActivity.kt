package mesh.shadowmesh.app

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.view.Gravity
import android.graphics.Color
import androidx.appcompat.app.AppCompatActivity

/**
 * Cover activity — shown after [PanicWipeManager] completes a full wipe.
 *
 * This activity must appear to be an unrelated, benign system utility.
 * No SHADOWMESH branding. No indication that a wipe occurred. The user
 * (or an adversary holding the device) should see a plausible generic app.
 *
 * Manifest attributes (declared in AndroidManifest.xml):
 *   android:label="File Manager"         — shown in Recents and title bar
 *   android:taskAffinity="mesh.shadowmesh.cover" — separate task from main app
 *   android:excludeFromRecents="true"    — does not appear in Recents alongside SHADOWMESH
 *   android:icon="@mipmap/ic_cover"      — generic utility icon (folder/file icon)
 *
 * Back press: exits the activity normally. The "File Manager" appears to close.
 * No crash, no "app not installed" message, no return to SHADOWMESH.
 *
 * After a wipe, SHADOWMESH's main Activity cannot start because all Room databases,
 * Keystore entries, and SharedPreferences are deleted. Attempting to launch the main
 * app results in the Application init failing silently and returning here again.
 *
 * Implementation note: this file contains no import of any SHADOWMESH class other
 * than what is strictly needed for Android lifecycle. This is intentional — the
 * cover activity must compile and run even if the entire SHADOWMESH module tree is
 * in an inconsistent state post-wipe.
 */
class CoverActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Build a minimal "File Manager" UI programmatically — no layout file
        // to inadvertently reveal SHADOWMESH resource names in heap dumps or
        // APK analysis tools.
        val root = LinearLayout(this).apply {
            orientation  = LinearLayout.VERTICAL
            gravity      = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(Color.WHITE)
        }

        val title = TextView(this).apply {
            text     = "File Manager"
            textSize = 22f
            setTextColor(Color.parseColor("#212121"))
            setPadding(0, 0, 0, 16)
        }

        val subtitle = TextView(this).apply {
            text     = "No files to display."
            textSize = 16f
            setTextColor(Color.parseColor("#757575"))
        }

        root.addView(title)
        root.addView(subtitle)
        setContentView(root)

        // Title bar will show the android:label="File Manager" from manifest.
        supportActionBar?.title = "File Manager"
    }
}
