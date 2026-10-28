package dev.devicesentinel.device_sentinel_security

import android.content.Context
import android.os.Build
import android.os.Looper
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/** Frida, hooking-framework and reverse-engineering-tool checks. */
internal object InstrumentationChecks {
    private val fridaPaths = arrayOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/sdcard/frida-server",
        "/system/bin/frida-server",
        "/system/xbin/frida-server"
    )

    // Matched against the FILE NAME of each mapping, not the whole line: the
    // path includes the host's package name, so "gadget" on the full line
    // would flag every user of an app called com.example.gadgetstore. Frida's
    // own names are matched as tokens, not the bare word "frida", which would
    // also flag a library called libfriday.so.
    private val fridaLibraryNeedles = arrayOf("frida-agent", "frida-gadget", "fridagadget")
    private val fridaLibraryNames = setOf("libgadget.so", "gadget.so")
    private val toolMapNeedles = arrayOf("libreveal", "sslkillswitch")

    // Thread names of Frida's JavaScript runtime and worker pool. They show in
    // /proc/self/task/*/comm, never in /proc/self/maps.
    private val fridaThreadNames = setOf("gum-js-loop", "pool-frida")

    // frida-server's default listeners. 0x69C2 / 0x69C3 in /proc/net/tcp.
    private val fridaPorts = intArrayOf(27042, 27043)
    private const val PORT_PROBE_TIMEOUT_MS = 150

    private val xposedPaths = arrayOf(
        "/system/framework/XposedBridge.jar",
        "/system/xbin/xposed",
        "/data/data/de.robv.android.xposed.installer"
    )

    // Declared in this plugin's AndroidManifest <queries> block; see
    // EnvironmentChecks.rootManagerPackages for why that matters.
    private val toolPackages = arrayOf(
        // Xposed installers
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "org.lsposed.manager",
        // Substrate / hooking
        "com.saurik.substrate",
        // Network interception
        "com.raureif.inetstat",
        "com.egorovandreyrm.pcapremote",
        "com.minhui.networkcapture",
        "app.greyshirts.sslcapture",
        // Root / kernel tooling
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "eu.chainfire.supersu",
        // Game Guardian / patchers / memory editors
        "catch_.me_.if_.you_.can_",
        "com.github.nicehash.luckypatchers",
        "com.chelpus.lackypatch",
        "com.forpda.lp",
        // Virtual environments (used to clone and tamper with apps)
        "com.bly.dkplat",
        "com.lbe.parallel.intl",
        "io.va.exposed"
    )

    private class MapsScan(val frida: Boolean, val tools: Boolean)

    private fun scanMaps(): MapsScan {
        var frida = false
        var tools = false
        try {
            File("/proc/self/maps").useLines { lines ->
                for (line in lines) {
                    val slash = line.lastIndexOf('/')
                    if (slash < 0) continue
                    val name = line.substring(slash + 1).lowercase()
                    if (!frida && isFridaLibraryName(name)) frida = true
                    if (!tools && toolMapNeedles.any { name.contains(it) }) tools = true
                    if (frida && tools) break
                }
            }
        } catch (_: Exception) {
            // Unreadable maps is not evidence of anything.
        }
        return MapsScan(frida, tools)
    }

    /** Runs the Frida and tool checks with a single read of /proc/self/maps. */
    fun check(context: Context, signals: Signals): Pair<Boolean, Boolean> {
        val maps = scanMaps()
        return Pair(hasFrida(maps, signals), hasReverseEngineeringTools(context, maps, signals))
    }

    /** [name] is a lower-cased mapping file name, possibly "x.so (deleted)". */
    internal fun isFridaLibraryName(name: String): Boolean {
        val file = name.removeSuffix(" (deleted)")
        return fridaLibraryNeedles.any { file.contains(it) } || file in fridaLibraryNames
    }

    internal fun isFridaThreadName(name: String): Boolean = name.trim() in fridaThreadNames

    private fun hasFrida(maps: MapsScan, signals: Signals): Boolean {
        // No `ps` scan: with hidepid on /proc an app only sees its own
        // processes, so frida-server (running as root) is invisible to it, and
        // forking `ps` on every tick costs real time on the check thread.
        if (fridaPaths.any { File(it).exists() }) return signals.hit("frida.path")
        if (maps.frida) return signals.hit("frida.maps")
        if (hasFridaThread()) return signals.hit("frida.thread")
        if (fridaPortInProcNet()) return signals.hit("frida.proc_net")
        if (fridaPortAcceptsConnections()) return signals.hit("frida.port")
        return false
    }

    private fun hasFridaThread(): Boolean = try {
        File("/proc/self/task").listFiles().orEmpty().any { task ->
            try {
                isFridaThreadName(File(task, "comm").readText())
            } catch (_: Exception) {
                false // The thread exited between the listing and the read.
            }
        }
    } catch (_: Exception) {
        false
    }

    // Android 10+ denies apps read access to /proc/net (SELinux
    // proc_net_tcp_udp). Trying anyway never succeeds and writes an `avc:
    // denied` audit line on every monitor tick, so it is only attempted on
    // older releases; the loopback probe below covers current ones.
    private fun fridaPortInProcNet(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) return false
        return try {
            File("/proc/net/tcp").useLines { lines ->
                lines.any { it.contains(":69C2") || it.contains(":69C3") }
            }
        } catch (_: Exception) {
            false
        }
    }

    // Needs the INTERNET permission; without it connect() throws and this
    // reports false.
    private fun fridaPortAcceptsConnections(): Boolean = fridaPorts.any { port ->
        try {
            Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), PORT_PROBE_TIMEOUT_MS) }
            true
        } catch (_: Exception) {
            false
        }
    }

    fun hasHookingFramework(signals: Signals): Boolean {
        // Classic Xposed boots the zygote through XposedBridge.main, so it sits
        // at the bottom of the MAIN thread's stack. This runs on the plugin's
        // background queue, whose own stack never has it; that stack is still
        // scanned for hooked frames between here and the channel handler.
        val stacks = sequenceOf(Looper.getMainLooper().thread.stackTrace, Throwable().stackTrace)
        if (stacks.any { frames -> frames.any { isXposedFrame(it.className) } }) {
            return signals.hit("hook.xposed_stack")
        }
        if (isXposedBridgeLoaded()) return signals.hit("hook.xposed_class")
        if (xposedPaths.any { File(it).exists() }) return signals.hit("hook.xposed_path")
        return false
    }

    internal fun isXposedFrame(className: String): Boolean =
        className.startsWith("de.robv.android.xposed.") || className.contains("XposedBridge")

    // Xposed puts its bridge on the boot class path. An app never ships it in
    // its own dex, so asking the system class loader cannot hit app code.
    private fun isXposedBridgeLoaded(): Boolean = try {
        ClassLoader.getSystemClassLoader().loadClass("de.robv.android.xposed.XposedBridge")
        true
    } catch (_: ClassNotFoundException) {
        false
    } catch (_: LinkageError) {
        false
    }

    private fun hasReverseEngineeringTools(
        context: Context,
        maps: MapsScan,
        signals: Signals
    ): Boolean {
        if (toolPackages.any { EnvironmentChecks.isPackageInstalled(context, it) }) {
            return signals.hit("tools.package")
        }
        if (maps.tools) return signals.hit("tools.maps")
        return false
    }
}
