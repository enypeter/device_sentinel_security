import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  group('DeviceSecurityReport.fromChannelReply', () {
    test('raises exactly the threats the reply marks true', () {
      final DeviceSecurityReport report = DeviceSecurityReport.fromChannelReply(
        nativeReply(
          'n',
          threats: <DeviceThreat>{DeviceThreat.rooted, DeviceThreat.frida},
          signals: <String>['root.path', 'frida.maps'],
        ),
        checkedAt: fixedTime,
      );

      expect(report.threats, <DeviceThreat>{
        DeviceThreat.rooted,
        DeviceThreat.frida,
      });
      expect(report.signals, <String>['root.path', 'frida.maps']);
      expect(report.isClean, isFalse);
      expect(report.has(DeviceThreat.frida), isTrue);
      expect(report.has(DeviceThreat.emulator), isFalse);
    });

    test('reads missing keys as not detected and ignores unknown ones', () {
      final DeviceSecurityReport report = DeviceSecurityReport.fromChannelReply(
        <Object?, Object?>{'nonce': 'n', 'futureThreat': true, 'emulator': 1},
        checkedAt: fixedTime,
      );

      expect(report.isClean, isTrue);
      expect(report.signals, isEmpty);
    });

    test('drops non-string signals', () {
      final DeviceSecurityReport report = DeviceSecurityReport.fromChannelReply(
        <Object?, Object?>{
          'signals': <Object?>['ok', 3, null],
        },
        checkedAt: fixedTime,
      );

      expect(report.signals, <String>['ok']);
    });
  });

  test('failed() carries only checkFailed and the reason', () {
    final DeviceSecurityReport report = DeviceSecurityReport.failed(
      'timeout',
      checkedAt: fixedTime,
    );

    expect(report.threats, <DeviceThreat>{DeviceThreat.checkFailed});
    expect(report.failure, 'timeout');
  });

  test('threats and signals cannot be mutated after construction', () {
    final DeviceSecurityReport report = reportWith(
      <DeviceThreat>{DeviceThreat.emulator},
      signals: <String>['emulator.hardware'],
    );

    expect(
      () => report.threats.add(DeviceThreat.frida),
      throwsUnsupportedError,
    );
    expect(() => report.signals.add('x'), throwsUnsupportedError);
  });

  test('toTelemetry has one boolean per threat and no free text', () {
    final Map<String, Object> telemetry = reportWith(
      <DeviceThreat>{DeviceThreat.tampered},
      signals: <String>['tamper.signature'],
    ).toTelemetry();

    expect(telemetry['sentinel_tampered'], isTrue);
    expect(telemetry['sentinel_emulator'], isFalse);
    expect(telemetry['sentinel_signals'], 'tamper.signature');
    expect(telemetry.containsKey('sentinel_failure'), isFalse);
    expect(
      telemetry.keys.where((String key) => key.startsWith('sentinel_')),
      hasLength(DeviceThreat.values.length + 1),
    );
  });

  test('equality compares content, not identity', () {
    expect(
      reportWith(<DeviceThreat>{DeviceThreat.frida, DeviceThreat.rooted}),
      reportWith(<DeviceThreat>{DeviceThreat.rooted, DeviceThreat.frida}),
    );
    expect(
      reportWith(<DeviceThreat>{DeviceThreat.frida}),
      isNot(reportWith(<DeviceThreat>{DeviceThreat.rooted})),
    );
  });
}
