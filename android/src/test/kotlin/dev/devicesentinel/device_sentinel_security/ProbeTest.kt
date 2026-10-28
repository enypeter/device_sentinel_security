package dev.devicesentinel.device_sentinel_security

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** JVM tests for the probe logic that does not need an Android runtime. */
class ProbeTest {
    @Test
    fun fridaLibraryNamesMatchFridaButNotLookalikes() {
        listOf(
            "frida-agent-64.so",
            "memfd:frida-agent-64.so (deleted)",
            "libfrida-gadget.so",
            "libgadget.so",
            "gadget.so (deleted)"
        ).forEach { assertTrue(it, InstrumentationChecks.isFridaLibraryName(it)) }

        listOf("libfriday.so", "libfridasync.so", "libgadgetstore.so", "libflutter.so")
            .forEach { assertFalse(it, InstrumentationChecks.isFridaLibraryName(it)) }
    }

    @Test
    fun fridaThreadNamesComeFromCommFiles() {
        assertTrue(InstrumentationChecks.isFridaThreadName("gum-js-loop\n"))
        assertTrue(InstrumentationChecks.isFridaThreadName("pool-frida\n"))
        assertFalse(InstrumentationChecks.isFridaThreadName("1.ui\n"))
    }

    @Test
    fun xposedFramesAreRecognised() {
        assertTrue(InstrumentationChecks.isXposedFrame("de.robv.android.xposed.XposedBridge"))
        assertTrue(InstrumentationChecks.isXposedFrame("com.elderdrivers.riru.edxp.XposedBridge"))
        assertFalse(InstrumentationChecks.isXposedFrame("android.app.ActivityThread"))
    }

    @Test
    fun anUnreadableSignatureIsNotCachedAsTampered() {
        val ours = byteArrayOf(1, 2, 3)
        val allowed = setOf(sha256(ours), "only-in-this-test-1")

        val first = Signals()
        assertTrue(TamperCheck.check(allowed, first) { throw RuntimeException("binder died") })
        assertEquals(listOf("tamper.unverifiable"), first.toList())

        // The next check reads again and finds our certificate.
        val second = Signals()
        assertFalse(TamperCheck.check(allowed, second) { listOf(ours) })
        assertTrue(second.toList().isEmpty())
    }

    @Test
    fun aSuccessfulReadIsCachedForTheProcess() {
        val allowed = setOf("only-in-this-test-2")
        var reads = 0

        assertTrue(TamperCheck.check(allowed, Signals()) { reads++; listOf(byteArrayOf(9)) })
        val cached = Signals()
        assertTrue(TamperCheck.check(allowed, cached) { reads++; listOf(byteArrayOf(9)) })

        assertEquals(1, reads)
        assertEquals(listOf("tamper.signature"), cached.toList())
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
