package mesh.shadowmesh.distribution.visual

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.booleans.shouldBeTrue
import mesh.shadowmesh.distribution.AppArtifactDescriptor
import kotlin.random.Random

/**
 * Proves the camera-channel claim: a file encoded as a looping fountain-coded QR stream can be
 * reconstructed by a receiver that MISSES frames and sees them OUT OF ORDER — which is exactly
 * what a phone camera filming a screen experiences.
 */
class VisualDistributionTest : DescribeSpec({

    fun fakeDescriptor() = AppArtifactDescriptor(
        versionCode = 1, versionName = "1.0",
        manifestHash = ByteArray(32) { 1 }, apkSha256 = ByteArray(32) { 2 },
        signingCertHash = "ab".repeat(32), minSdk = 29, signature = ByteArray(64) { 3 }
    )

    describe("LT fountain round-trip (ideal channel)") {
        it("recovers exactly with no loss") {
            val k = 50; val bs = 256
            val file = ByteArray(k * bs - 17) { (it * 31 % 256).toByte() }   // not block-aligned
            val enc = VisualFrameProtocol.StreamEncoder(file, fakeDescriptor(), blockSize = bs, seed = 12345L)
            val rx = VisualFrameProtocol.StreamReceiver()
            rx.offer(VisualFrameProtocol.parseFrame(enc.headerFrame()))
            var seq = 0L
            while (!rx.isComplete && seq < 5000) {
                rx.offer(VisualFrameProtocol.parseFrame(enc.dataFrame(seq))); seq++
            }
            rx.isComplete.shouldBeTrue()
            rx.assembleFile()!!.contentEquals(file).shouldBeTrue()
        }
    }

    describe("lossy + out-of-order channel (camera reality)") {
        it("reconstructs despite ~30% dropped frames and shuffling") {
            val k = 80; val bs = 512
            val file = ByteArray(k * bs - 123) { Random(7).nextInt().toByte() }
            val desc = fakeDescriptor()
            val enc = VisualFrameProtocol.StreamEncoder(file, desc, blockSize = bs, seed = 99L)

            // Seeder emits a long loop; channel drops 30% and reorders within windows.
            val rng = Random(2024)
            val rx = VisualFrameProtocol.StreamReceiver()
            rx.offer(VisualFrameProtocol.parseFrame(enc.headerFrame()))

            var seq = 0L
            val window = ArrayList<ByteArray>()
            while (!rx.isComplete && seq < 20000) {
                // build a window of 20 frames, drop ~30%, shuffle, deliver
                window.clear()
                repeat(20) {
                    if (rng.nextDouble() > 0.30) window.add(enc.dataFrame(seq))
                    seq++
                }
                window.shuffle(rng)
                for (f in window) {
                    if (rx.offer(VisualFrameProtocol.parseFrame(f))) break
                }
            }

            rx.isComplete.shouldBeTrue()
            val out = rx.assembleFile()!!
            out.contentEquals(file).shouldBeTrue()
            // The descriptor rode in on the header frame and survived.
            rx.descriptor shouldBe desc
        }

        it("a corrupted frame (bad CRC) is rejected, not fed into the decoder") {
            val enc = VisualFrameProtocol.StreamEncoder(ByteArray(1000) { 5 }, fakeDescriptor(), blockSize = 256, seed = 1L)
            val good = enc.dataFrame(0)
            val corrupt = good.copyOf().also { it[10] = (it[10] + 1).toByte() }
            VisualFrameProtocol.parseFrame(corrupt) shouldBe VisualFrameProtocol.Frame.Invalid
        }
    }

    describe("late joiner") {
        it("syncs from a periodic header even if it missed the first ones") {
            val k = 40; val bs = 256
            val file = ByteArray(k * bs) { it.toByte() }
            val enc = VisualFrameProtocol.StreamEncoder(file, fakeDescriptor(), blockSize = bs, seed = 55L)
            val rx = VisualFrameProtocol.StreamReceiver()
            // Receiver starts mid-stream: skip first 30 data frames entirely, no header yet.
            var seq = 30L
            // Data frames before any header are harmless no-ops.
            repeat(5) { rx.offer(VisualFrameProtocol.parseFrame(enc.dataFrame(seq))); seq++ }
            rx.isComplete shouldBe false
            // Header arrives (periodic), then data flows.
            rx.offer(VisualFrameProtocol.parseFrame(enc.headerFrame()))
            while (!rx.isComplete && seq < 5000) {
                rx.offer(VisualFrameProtocol.parseFrame(enc.dataFrame(seq))); seq++
            }
            rx.isComplete.shouldBeTrue()
            rx.assembleFile()!!.contentEquals(file).shouldBeTrue()
        }
    }
})
