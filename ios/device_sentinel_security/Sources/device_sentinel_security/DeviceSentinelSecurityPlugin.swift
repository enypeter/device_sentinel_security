import Flutter
import UIKit

/// Runs the device checks for `DeviceSentinel.checkDevice()`.
public class DeviceSentinelSecurityPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        // The checks stat dozens of paths, walk every loaded image and open
        // loopback sockets; none of that belongs on the main thread. The task
        // queue is serial, so checks never overlap.
        let messenger = registrar.messenger()
        let taskQueue = messenger.makeBackgroundTaskQueue?()
        let channel = FlutterMethodChannel(
            name: "device_sentinel_security",
            binaryMessenger: messenger,
            codec: FlutterStandardMethodCodec.sharedInstance(),
            taskQueue: taskQueue
        )
        registrar.addMethodCallDelegate(DeviceSentinelSecurityPlugin(), channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "checkDevice":
            result(checkDevice(arguments: call.arguments as? [String: Any] ?? [:]))
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func checkDevice(arguments: [String: Any]) -> [String: Any] {
        let nonce = arguments["nonce"] as? String ?? ""
        let bundleIds = arguments["iosBundleIds"] as? [String] ?? []
        let signals = Signals()
        let images = InstrumentationChecks.loadedImageNames()

        return [
            "nonce": nonce,
            "emulator": EnvironmentChecks.isSimulator(signals),
            "rooted": false,
            "jailbroken": EnvironmentChecks.isJailbroken(signals),
            "debuggerAttached": EnvironmentChecks.isDebuggerAttached(signals),
            "debuggableBuild": EnvironmentChecks.isDebuggableBuild(signals),
            "frida": InstrumentationChecks.hasFrida(images: images, signals),
            "hookingFramework": InstrumentationChecks.hasHookingFramework(images: images, signals),
            "reverseEngineeringTools": false,
            "tampered": TamperCheck.isTampered(expectedBundleIds: bundleIds, images: images, signals),
            "signals": signals.fired,
        ]
    }
}
