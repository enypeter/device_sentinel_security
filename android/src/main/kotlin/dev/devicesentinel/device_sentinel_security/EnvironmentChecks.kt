package dev.devicesentinel.device_sentinel_security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File

/** Emulator, root and debugger checks. */
internal object EnvironmentChecks {
    // Build properties and the debuggable flag cannot change without a
    // reinstall, which kills the process, so they are computed once. The
    // runtime monitor calls these on every tick.
    @Volatile private var cachedEmulator: Boolean? = null
    @Volatile private var cachedEmulatorSignal: String? = null

    private val suPaths = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/system/app/SuperSU.apk",
        "/sbin/magisk",
        "/system/xbin/magisk",
        "/data/adb/magisk",
        "/cache/magisk",
        "/dev/.magisk"
    )

    // Each package here is declared in this plugin's AndroidManifest <queries>
    // block. Without that, Android 11+ hides other apps and every lookup below
    // reports "not installed".
    private val rootManagerPackages = arrayOf(
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk"
    )

    fun isEmulator(signals: Signals): Boolean {
        val cached = cachedEmulator
        if (cached != null) {
            cachedEmulatorSignal?.let { signals.hit(it) }
            return cached
        }
        val signal = emulatorSignal()
        cachedEmulatorSignal = signal
        cachedEmulator = signal != null
        signal?.let { signals.hit(it) }
        return signal != null
    }

    private fun emulatorSignal(): String? {
        val fingerprint = Build.FINGERPRINT
        val model = Build.MODEL
        val hardware = Build.HARDWARE
        return when {
            fingerprint.startsWith("generic") || fingerprint.startsWith("unknown") ->
                "emulator.fingerprint"
            model.contains("google_sdk") || model.contains("Emulator") ||
                model.contains("Android SDK built for") -> "emulator.model"
            Build.MANUFACTURER.contains("Genymotion") -> "emulator.manufacturer"
            Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ->
                "emulator.brand"
            "google_sdk" == Build.PRODUCT -> "emulator.product"
            hardware.contains("goldfish") || hardware.contains("ranchu") ->
                "emulator.hardware"
            listOf(Build.BOARD, Build.BOOTLOADER, hardware, Build.PRODUCT)
                .any { it.lowercase().contains("nox") } -> "emulator.nox"
            else -> null
        }
    }

    fun isRooted(context: Context, signals: Signals): Boolean {
        if (suPaths.any { File(it).exists() }) return signals.hit("root.path")
        if (rootManagerPackages.any { isPackageInstalled(context, it) }) {
            return signals.hit("root.package")
        }
        // Same answer as `which su`, without forking a process on every tick.
        val pathDirs = System.getenv("PATH")?.split(":").orEmpty()
        if (pathDirs.any { it.isNotEmpty() && File(it, "su").exists() }) {
            return signals.hit("root.su_on_path")
        }
        return false
    }

    fun isDebuggerAttached(signals: Signals): Boolean {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return signals.hit("debugger.jdwp")
        }
        return false
    }

    /** Runtime flag: informational only, a repackager can set it. */
    fun isDebuggableBuild(context: Context, signals: Signals): Boolean {
        val debuggable =
            (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (debuggable) signals.hit("build.debuggable")
        return debuggable
    }

    fun isPackageInstalled(context: Context, packageName: String): Boolean = try {
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, 0)
        }
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (_: RuntimeException) {
        false
    }
}
