/// Client-side device security checks: emulator, root, jailbreak, debugger,
/// Frida, hooking and tamper detection, with a runtime monitor and a
/// host-configurable policy.
///
/// Every check runs on the device and can be defeated by an attacker who
/// controls it. Use the result to raise the cost of casual tampering and to
/// gather signal — pair it with server-side attestation (Play Integrity,
/// App Attest) for anything that must be trusted.
library;

export 'src/device_security_report.dart';
export 'src/device_sentinel.dart';
export 'src/device_threat.dart';
export 'src/platform/device_sentinel_platform.dart';
export 'src/platform/method_channel_device_sentinel.dart';
export 'src/sentinel_config.dart';
export 'src/sentinel_monitor.dart';
export 'src/sentinel_policy.dart';
export 'src/widgets/sentinel_guard.dart';
export 'src/widgets/sentinel_views.dart';
