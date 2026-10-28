import 'dart:io';

import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Runs the real native checks. Intended for an emulator / simulator debug
/// run: `flutter test integration_test -d <device>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('checkDevice reaches the native side and answers', (_) async {
    final DeviceSentinel sentinel = DeviceSentinel();

    final DeviceSecurityReport report = await sentinel.checkDevice();

    // The channel answered, echoed the nonce and produced a report.
    expect(report.failure, isNull, reason: report.toString());
    expect(report.has(DeviceThreat.checkFailed), isFalse);
    expect(report.has(DeviceThreat.channelMismatch), isFalse);

    // A debug build on an emulator/simulator must say so.
    expect(report.has(DeviceThreat.debuggableBuild), isTrue);
    expect(
      report.has(DeviceThreat.emulator),
      isTrue,
      reason: report.toString(),
    );

    // Platform-specific threats never leak across platforms.
    if (Platform.isIOS) {
      expect(report.has(DeviceThreat.rooted), isFalse);
      expect(report.has(DeviceThreat.reverseEngineeringTools), isFalse);
    } else {
      expect(report.has(DeviceThreat.jailbroken), isFalse);
    }

    // Tamper is skipped in debug builds.
    expect(report.has(DeviceThreat.tampered), isFalse);

    // A stock emulator/simulator is not instrumented: no false positives
    // from the Frida, thread, stack or swizzle probes.
    expect(report.has(DeviceThreat.frida), isFalse, reason: report.toString());
    expect(
      report.has(DeviceThreat.hookingFramework),
      isFalse,
      reason: report.toString(),
    );

    // ignore: avoid_print
    print('device_sentinel report: $report');
  });

  testWidgets('a second check gives the same answer', (_) async {
    final DeviceSentinel sentinel = DeviceSentinel();
    final DeviceSecurityReport first = await sentinel.checkDevice();
    final DeviceSecurityReport second = await sentinel.checkDevice();

    expect(second.threats, first.threats);
  });
}
