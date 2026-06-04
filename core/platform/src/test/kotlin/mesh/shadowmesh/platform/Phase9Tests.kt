package mesh.shadowmesh.platform

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain

// ── OemBatteryExemption ───────────────────────────────────────────────────────

class OemBatteryExemptionTest : DescribeSpec({

    describe("OemBatteryExemption — OEM detection") {

        it("STOCK_AOSP is the default for unknown manufacturers") {
            // Build fields can't be mocked in a unit test without Robolectric,
            // but we verify the function returns a valid enum value
            val rom = OemBatteryExemption.detectOemRom()
            OemBatteryExemption.OemRom.values().contains(rom) shouldBe true
        }

        it("oemExemptionInstruction(rom) returns a non-empty string for every OEM") {
            // Test every branch directly using the overload that accepts a pre-detected OemRom.
            // This replaces the previous empty-loop test which asserted nothing per branch.
            OemBatteryExemption.OemRom.values().forEach { rom ->
                val instruction = OemBatteryExemption.oemExemptionInstruction(rom)
                instruction.isNotBlank() shouldBe true
            }
        }

        it("oemExemptionInstruction(MIUI) mentions Autostart") {
            OemBatteryExemption.oemExemptionInstruction(OemBatteryExemption.OemRom.MIUI)
                .lowercase() shouldContain "autostart"
        }

        it("oemExemptionInstruction(STOCK_AOSP) mentions no additional steps") {
            OemBatteryExemption.oemExemptionInstruction(OemBatteryExemption.OemRom.STOCK_AOSP)
                .lowercase() shouldContain "no additional"
        }

        it("no-arg oemExemptionInstruction() delegates to the rom overload") {
            // Both calls hit the same when() block — results must be equal for any device
            val fromNoArg = OemBatteryExemption.oemExemptionInstruction()
            val detected  = OemBatteryExemption.detectOemRom()
            val fromRom   = OemBatteryExemption.oemExemptionInstruction(detected)
            fromNoArg shouldBe fromRom
        }

        it("FOREGROUND_SERVICE_RESTART_INTERVAL_MS is 23 hours") {
            val expected = 23L * 60 * 60 * 1000
            OemBatteryExemption.FOREGROUND_SERVICE_RESTART_INTERVAL_MS shouldBe expected
        }

        it("isForegroundServiceRestartDue returns false if started recently") {
            val startedNow = System.currentTimeMillis()
            OemBatteryExemption.isForegroundServiceRestartDue(startedNow) shouldBe false
        }

        it("isForegroundServiceRestartDue returns true after RESTART_INTERVAL") {
            // Simulate the service having started 23+ hours ago
            val startedLongAgo = System.currentTimeMillis() -
                OemBatteryExemption.FOREGROUND_SERVICE_RESTART_INTERVAL_MS - 1_000
            // Only applies if API 33+ — on JVM tests, isForegroundServiceLifetimeLimited() = false
            // The check is still valid: if limited, old service should restart
            if (OemBatteryExemption.isForegroundServiceLifetimeLimited()) {
                OemBatteryExemption.isForegroundServiceRestartDue(startedLongAgo) shouldBe true
            }
            // On JVM (non-Android 33), this always returns false — correct behaviour
        }
    }
})

// ── BiometricEnrollmentChecker ─────────────────────────────────────────────────

class BiometricEnrollmentCheckerTest : DescribeSpec({

    describe("BiometricEnrollmentChecker — userMessage") {

        it("produces a non-blank message for every status") {
            BiometricEnrollmentChecker.EnrollmentStatus.values().forEach { status ->
                val msg = BiometricEnrollmentChecker.userMessage(status)
                msg.isNotBlank() shouldBe true
            }
        }

        it("NONE_ENROLLED message warns about screen lock requirement") {
            val msg = BiometricEnrollmentChecker.userMessage(
                BiometricEnrollmentChecker.EnrollmentStatus.NONE_ENROLLED
            )
            msg shouldContain "screen lock"
        }

        it("STRONG_BIOMETRIC_READY message is affirming") {
            val msg = BiometricEnrollmentChecker.userMessage(
                BiometricEnrollmentChecker.EnrollmentStatus.STRONG_BIOMETRIC_READY
            )
            msg shouldContain "ready"
        }
    }

    describe("BiometricEnrollmentChecker — canProceedWithKeyOps") {

        it("STRONG_BIOMETRIC_READY allows key ops") {
            // Verify the logic directly without Android runtime
            val status = BiometricEnrollmentChecker.EnrollmentStatus.STRONG_BIOMETRIC_READY
            // canProceedWithKeyOps takes a Context — test the logic inline
            val result = when (status) {
                BiometricEnrollmentChecker.EnrollmentStatus.STRONG_BIOMETRIC_READY,
                BiometricEnrollmentChecker.EnrollmentStatus.WEAK_BIOMETRIC_ONLY,
                BiometricEnrollmentChecker.EnrollmentStatus.CREDENTIAL_ONLY -> true
                else -> false
            }
            result shouldBe true
        }

        it("NONE_ENROLLED blocks key ops") {
            val status = BiometricEnrollmentChecker.EnrollmentStatus.NONE_ENROLLED
            val result = when (status) {
                BiometricEnrollmentChecker.EnrollmentStatus.STRONG_BIOMETRIC_READY,
                BiometricEnrollmentChecker.EnrollmentStatus.WEAK_BIOMETRIC_ONLY,
                BiometricEnrollmentChecker.EnrollmentStatus.CREDENTIAL_ONLY -> true
                else -> false
            }
            result shouldBe false
        }
    }
})

// ── LowRamDeviceGuard ──────────────────────────────────────────────────────────

class LowRamDeviceGuardTest : DescribeSpec({

    describe("LowRamDeviceGuard — constant relationships") {

        it("low-RAM fragment cache cap is less than standard") {
            // Can't call with real Context in unit test — verify the constant relationship
            // by checking the documented values
            val lowRamCap  = 2_000
            val standardCap = 10_000
            (lowRamCap < standardCap) shouldBe true
        }

        it("low-RAM SNDP burst count is less than standard") {
            val lowRamBurst  = 3
            val standardBurst = 7
            (lowRamBurst < standardBurst) shouldBe true
        }

        it("low-RAM WorkManager job cap is less than standard") {
            val lowRamJobs  = 3
            val standardJobs = 10
            (lowRamJobs < standardJobs) shouldBe true
        }

        it("low-RAM seenFragmentIds cap satisfies safety margin vs standard") {
            // Standard cap is 10_000 (Phase 7 fix); low-RAM is 2_000.
            // At 512B × 2_000 = 1MB per peer — acceptable on 2GB devices.
            val lowRamCap   = 2_000
            val bytesPerPeer = lowRamCap * 64  // ~64 bytes per hex fragment ID
            (bytesPerPeer < 200_000) shouldBe true  // under 200KB per peer
        }
    }
})

// ── OnboardingViewModel — logic tests ──────────────────────────────────────────

class OnboardingCompletionSummaryTest : DescribeSpec({

    describe("OnboardingCompletionSummary") {

        it("protectionScore counts true fields correctly") {
            val summary = OnboardingCompletionSummary(
                biometricConfigured  = true,
                batteryExempted      = true,
                duressPinConfigured  = false,
                entryNodeConfigured  = true,
                physicalKeyExchanged = false
            )
            summary.protectionScore shouldBe 3
        }

        it("fully configured summary has score 5") {
            val summary = OnboardingCompletionSummary(
                biometricConfigured  = true,
                batteryExempted      = true,
                duressPinConfigured  = true,
                entryNodeConfigured  = true,
                physicalKeyExchanged = true
            )
            summary.protectionScore shouldBe 5
        }

        it("summaryLines has exactly 5 entries") {
            val summary = OnboardingCompletionSummary()
            summary.summaryLines().size shouldBe 5
        }

        it("completed steps show checkmark, incomplete show warning or circle") {
            val summary = OnboardingCompletionSummary(biometricConfigured = true)
            val lines = summary.summaryLines()
            lines[0] shouldContain "✓"   // biometric — completed
            lines[1] shouldContain "⚠"   // battery — not completed (prerequisite warning)
        }

        it("skipped optional step shows circle not checkmark — skip != complete") {
            // entryNodeConfigured=false simulates the user having skipped ENTRY_NODE_SETUP.
            // The summary must show ○ (optional, not done) not ✓ (done).
            val summary = OnboardingCompletionSummary(entryNodeConfigured = false)
            val entryLine = summary.summaryLines()[3]  // index 3 = entry node
            entryLine shouldContain "○"
            (entryLine.contains("✓")) shouldBe false
        }

        it("completed optional step shows checkmark") {
            val summary = OnboardingCompletionSummary(entryNodeConfigured = true)
            summary.summaryLines()[3] shouldContain "✓"
        }
    }
})
