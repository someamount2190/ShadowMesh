package mesh.shadowmesh.platform

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe

/**
 * Phase 8/9 — VpnServiceBridge consent-state tests.
 * Exercises the pure persistence-driven logic (no Android Context) via a fake
 * [VpnConsentStore]: one-time grant, persistence across restart, and revoke/re-request.
 */
class VpnServiceBridgeTest : DescribeSpec({

    class FakeConsentStore : VpnConsentStore {
        var granted = false
        var revoked = false
        override fun wasGranted() = granted
        override fun wasRevoked() = revoked
        override fun setGranted(value: Boolean) { granted = value }
        override fun setRevoked(value: Boolean) { revoked = value }
    }

    describe("initial state") {
        it("is NOT_REQUESTED on a fresh install and needs consent") {
            val bridge = VpnServiceBridge(FakeConsentStore())
            bridge.permissionState() shouldBe VpnServiceBridge.PermissionState.NOT_REQUESTED
            bridge.needsConsent() shouldBe true
        }
    }

    describe("granting consent") {
        it("transitions to GRANTED and no longer needs consent") {
            val store = FakeConsentStore()
            val bridge = VpnServiceBridge(store)
            bridge.onConsentResult(granted = true)
            bridge.permissionState() shouldBe VpnServiceBridge.PermissionState.GRANTED
            bridge.needsConsent() shouldBe false
        }

        it("persists across restart (new bridge over same store stays GRANTED)") {
            val store = FakeConsentStore()
            VpnServiceBridge(store).onConsentResult(granted = true)
            // Simulate process restart: brand-new bridge, same persisted store.
            val restarted = VpnServiceBridge(store)
            restarted.permissionState() shouldBe VpnServiceBridge.PermissionState.GRANTED
            restarted.needsConsent() shouldBe false
        }
    }

    describe("revocation") {
        it("moves a granted bridge to REVOKED and requires re-request") {
            val store = FakeConsentStore()
            val bridge = VpnServiceBridge(store)
            bridge.onConsentResult(granted = true)
            bridge.onRevoked()
            bridge.permissionState() shouldBe VpnServiceBridge.PermissionState.REVOKED
            bridge.needsConsent() shouldBe true
        }

        it("re-granting after revoke clears the revoked flag") {
            val store = FakeConsentStore()
            val bridge = VpnServiceBridge(store)
            bridge.onRevoked()
            bridge.onConsentResult(granted = true)
            bridge.permissionState() shouldBe VpnServiceBridge.PermissionState.GRANTED
        }
    }

    describe("denied consent dialog") {
        it("a false result leaves the bridge un-granted") {
            val store = FakeConsentStore()
            val bridge = VpnServiceBridge(store)
            bridge.onConsentResult(granted = false)
            bridge.permissionState() shouldBe VpnServiceBridge.PermissionState.NOT_REQUESTED
            bridge.needsConsent() shouldBe true
        }
    }
})
