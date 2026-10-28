package dev.devicesentinel.device_sentinel_security

import android.content.Context
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.StandardMethodCodec

/** Runs the device checks for `DeviceSentinel.checkDevice()`. */
class DeviceSentinelSecurityPlugin : FlutterPlugin, MethodCallHandler {
    private var channel: MethodChannel? = null
    private lateinit var context: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        // The checks read /proc, stat dozens of paths, make PackageManager
        // binder calls and open loopback sockets. A channel without a task
        // queue runs its handler on the Android main thread, and a runtime
        // monitor calls it every few seconds for the life of the process —
        // a recipe for ANRs. The background queue is serial, so checks never
        // overlap, and Result may be answered from it.
        val taskQueue = binding.binaryMessenger.makeBackgroundTaskQueue()
        channel = MethodChannel(
            binding.binaryMessenger,
            CHANNEL,
            StandardMethodCodec.INSTANCE,
            taskQueue
        ).also { it.setMethodCallHandler(this) }
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "checkDevice" -> {
                try {
                    result.success(checkDevice(call))
                } catch (e: Throwable) {
                    // Errors too (an odd ROM's NoSuchMethodError, an OOM): the
                    // embedding rethrows an Error from a task queue and kills
                    // the host app, and an advisory check must never do that.
                    result.error("check_failed", e.javaClass.simpleName, null)
                }
            }
            else -> result.notImplemented()
        }
    }

    private fun checkDevice(call: MethodCall): Map<String, Any> {
        val nonce = call.argument<String>("nonce") ?: ""
        val allowedSha256 = call.argument<List<String>>("androidSigningCertSha256")
            .orEmpty()
            .map { it.lowercase() }
            .toSet()

        val signals = Signals()
        val (frida, tools) = InstrumentationChecks.check(context, signals)
        return mapOf(
            "nonce" to nonce,
            "emulator" to EnvironmentChecks.isEmulator(signals),
            "rooted" to EnvironmentChecks.isRooted(context, signals),
            "jailbroken" to false,
            "debuggerAttached" to EnvironmentChecks.isDebuggerAttached(signals),
            "debuggableBuild" to EnvironmentChecks.isDebuggableBuild(context, signals),
            "frida" to frida,
            "hookingFramework" to InstrumentationChecks.hasHookingFramework(signals),
            "reverseEngineeringTools" to tools,
            "tampered" to TamperCheck.isTampered(context, allowedSha256, signals),
            "signals" to signals.toList()
        )
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
    }

    private companion object {
        const val CHANNEL = "device_sentinel_security"
    }
}
