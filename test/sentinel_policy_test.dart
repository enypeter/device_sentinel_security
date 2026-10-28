import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  group('responseTo', () {
    test('a clean report is ignored by every built-in policy', () {
      for (final SentinelPolicy policy in <SentinelPolicy>[
        SentinelPolicy.strict,
        SentinelPolicy.instrumentationOnly,
        SentinelPolicy.reportOnly,
        SentinelPolicy.off,
      ]) {
        expect(
          policy.responseTo(reportWith(const <DeviceThreat>{})),
          SentinelResponse.ignore,
        );
      }
    });

    test('strict blocks on emulator, instrumentationOnly only warns', () {
      final DeviceSecurityReport report = reportWith(<DeviceThreat>{
        DeviceThreat.emulator,
      });

      expect(SentinelPolicy.strict.responseTo(report), SentinelResponse.block);
      expect(
        SentinelPolicy.instrumentationOnly.responseTo(report),
        SentinelResponse.warn,
      );
    });

    test('blocking wins over warning in a mixed report', () {
      final DeviceSecurityReport report = reportWith(<DeviceThreat>{
        DeviceThreat.emulator,
        DeviceThreat.frida,
      });

      expect(
        SentinelPolicy.instrumentationOnly.responseTo(report),
        SentinelResponse.block,
      );
      expect(
        SentinelPolicy.instrumentationOnly.blocking(report),
        <DeviceThreat>{DeviceThreat.frida},
      );
      expect(SentinelPolicy.instrumentationOnly.warning(report), <DeviceThreat>{
        DeviceThreat.emulator,
      });
    });

    test('a threat in both sets counts as blocking only', () {
      const SentinelPolicy policy = SentinelPolicy(
        block: <DeviceThreat>{DeviceThreat.rooted},
        warn: <DeviceThreat>{DeviceThreat.rooted},
      );
      final DeviceSecurityReport report = reportWith(<DeviceThreat>{
        DeviceThreat.rooted,
      });

      expect(policy.warning(report), isEmpty);
      expect(policy.responseTo(report), SentinelResponse.block);
    });

    test('reportOnly never blocks', () {
      final DeviceSecurityReport everything = reportWith(
        DeviceThreat.values.toSet(),
      );

      expect(SentinelPolicy.reportOnly.blocking(everything), isEmpty);
      expect(
        SentinelPolicy.reportOnly.responseTo(everything),
        SentinelResponse.warn,
      );
    });
  });

  test('no built-in policy blocks on checkFailed or debuggableBuild', () {
    for (final SentinelPolicy policy in <SentinelPolicy>[
      SentinelPolicy.strict,
      SentinelPolicy.instrumentationOnly,
      SentinelPolicy.reportOnly,
      SentinelPolicy.off,
    ]) {
      expect(policy.block, isNot(contains(DeviceThreat.checkFailed)));
      expect(policy.block, isNot(contains(DeviceThreat.debuggableBuild)));
    }
  });

  group('selectForBuildMode', () {
    const SentinelPolicy release = SentinelPolicy.strict;
    const SentinelPolicy profile = SentinelPolicy.instrumentationOnly;

    test('release build uses the release policy', () {
      expect(
        SentinelPolicy.selectForBuildMode(
          isRelease: true,
          isProfile: false,
          release: release,
        ),
        release,
      );
    });

    test('profile build uses profile, falling back to debug', () {
      expect(
        SentinelPolicy.selectForBuildMode(
          isRelease: false,
          isProfile: true,
          release: release,
          profile: profile,
        ),
        profile,
      );
      expect(
        SentinelPolicy.selectForBuildMode(
          isRelease: false,
          isProfile: true,
          release: release,
        ),
        SentinelPolicy.reportOnly,
      );
    });

    test('debug build uses the debug policy', () {
      expect(
        SentinelPolicy.selectForBuildMode(
          isRelease: false,
          isProfile: false,
          release: release,
          debug: SentinelPolicy.off,
        ),
        SentinelPolicy.off,
      );
    });

    test('forBuildMode resolves to the debug policy under flutter test', () {
      expect(
        SentinelPolicy.forBuildMode(release: release),
        SentinelPolicy.reportOnly,
      );
    });
  });

  test('copyWith replaces only the given set', () {
    final SentinelPolicy policy = SentinelPolicy.strict.copyWith(
      block: <DeviceThreat>{DeviceThreat.frida},
    );

    expect(policy.block, <DeviceThreat>{DeviceThreat.frida});
    expect(policy.warn, SentinelPolicy.strict.warn);
  });
}
