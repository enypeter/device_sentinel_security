import 'dart:async';

import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';

import 'helpers.dart';

void main() {
  late MockDeviceSentinel sentinel;

  setUpAll(() => registerFallbackValue(Duration.zero));

  setUp(() => sentinel = MockDeviceSentinel());

  SentinelMonitor monitorWith({
    SentinelPolicy policy = SentinelPolicy.strict,
    int strikesToBlock = 3,
    bool stopOnBlock = true,
  }) => SentinelMonitor(
    sentinel: sentinel,
    policy: policy,
    strikesToBlock: strikesToBlock,
    stopOnBlock: stopOnBlock,
  );

  group('evaluate', () {
    test('a clean report yields nothing and resets the strikes', () {
      final SentinelMonitor monitor = monitorWith();
      monitor.evaluate(reportWith(<DeviceThreat>{DeviceThreat.rooted}));
      expect(monitor.strikes, 1);

      expect(monitor.evaluate(reportWith(const <DeviceThreat>{})), isNull);
      expect(monitor.strikes, 0);
    });

    test('live instrumentation blocks on first sight', () {
      final SentinelViolation? violation = monitorWith().evaluate(
        reportWith(<DeviceThreat>{DeviceThreat.frida}),
      );

      expect(violation!.response, SentinelResponse.block);
      expect(violation.threats, <DeviceThreat>{DeviceThreat.frida});
      expect(violation.strikes, 1);
    });

    test('other blocking threats warn until seen strikesToBlock times', () {
      final SentinelMonitor monitor = monitorWith();
      final DeviceSecurityReport rooted = reportWith(<DeviceThreat>{
        DeviceThreat.rooted,
      });

      expect(monitor.evaluate(rooted)!.response, SentinelResponse.warn);
      expect(monitor.evaluate(rooted)!.response, SentinelResponse.warn);
      expect(monitor.evaluate(rooted)!.response, SentinelResponse.block);
    });

    test('a clean check in between restarts the count', () {
      final SentinelMonitor monitor = monitorWith(strikesToBlock: 2);
      final DeviceSecurityReport rooted = reportWith(<DeviceThreat>{
        DeviceThreat.rooted,
      });

      monitor.evaluate(rooted);
      monitor.evaluate(reportWith(const <DeviceThreat>{}));

      expect(monitor.evaluate(rooted)!.response, SentinelResponse.warn);
    });

    test('a failed check keeps the strike count', () {
      // A check that times out every other tick must not keep a real threat
      // below strikesToBlock forever.
      final SentinelMonitor monitor = monitorWith(strikesToBlock: 2);
      final DeviceSecurityReport rooted = reportWith(<DeviceThreat>{
        DeviceThreat.rooted,
      });

      expect(monitor.evaluate(rooted)!.response, SentinelResponse.warn);
      monitor.evaluate(DeviceSecurityReport.failed('timeout'));
      expect(monitor.strikes, 1);

      expect(monitor.evaluate(rooted)!.response, SentinelResponse.block);
    });

    test('warn-only threats warn without counting strikes', () {
      final SentinelMonitor monitor = monitorWith(
        policy: SentinelPolicy.instrumentationOnly,
      );

      final SentinelViolation? violation = monitor.evaluate(
        reportWith(<DeviceThreat>{DeviceThreat.emulator}),
      );

      expect(violation!.response, SentinelResponse.warn);
      expect(violation.threats, <DeviceThreat>{DeviceThreat.emulator});
      expect(monitor.strikes, 0);
    });

    test('threats the policy ignores yield nothing', () {
      expect(
        monitorWith(
          policy: SentinelPolicy.off,
        ).evaluate(reportWith(DeviceThreat.values.toSet())),
        isNull,
      );
    });
  });

  group('running', () {
    late StreamController<DeviceSecurityReport> checks;

    setUp(() {
      checks = StreamController<DeviceSecurityReport>();
      when(
        () => sentinel.watch(interval: any(named: 'interval')),
      ).thenAnswer((_) => checks.stream);
    });

    test('forwards every report and every violation', () {
      fakeAsync((FakeAsync async) {
        final SentinelMonitor monitor = monitorWith();
        final List<DeviceSecurityReport> reports = <DeviceSecurityReport>[];
        final List<SentinelViolation> violations = <SentinelViolation>[];
        monitor.reports.listen(reports.add);
        monitor.violations.listen(violations.add);

        monitor.start();
        expect(monitor.isRunning, isTrue);
        checks.add(reportWith(const <DeviceThreat>{}));
        checks.add(reportWith(<DeviceThreat>{DeviceThreat.rooted}));
        async.flushMicrotasks();

        expect(reports, hasLength(2));
        expect(violations.single.response, SentinelResponse.warn);
        expect(monitor.lastCheckAt, fixedTime);
      });
    });

    test('stops itself after a block when stopOnBlock is set', () {
      fakeAsync((FakeAsync async) {
        final SentinelMonitor monitor = monitorWith();

        monitor.start();
        checks.add(reportWith(<DeviceThreat>{DeviceThreat.frida}));
        async.flushMicrotasks();

        expect(monitor.isRunning, isFalse);
        expect(checks.hasListener, isFalse);
      });
    });

    test('remembers the block and will not restart after it', () {
      fakeAsync((FakeAsync async) {
        final SentinelMonitor monitor = monitorWith();
        expect(monitor.blockedBy, isNull);

        monitor.start();
        checks.add(reportWith(<DeviceThreat>{DeviceThreat.frida}));
        async.flushMicrotasks();
        monitor.start();

        expect(monitor.blockedBy!.threats, <DeviceThreat>{DeviceThreat.frida});
        expect(monitor.isRunning, isFalse);
        verify(
          () => sentinel.watch(interval: any(named: 'interval')),
        ).called(1);
      });
    });

    test('keeps running after a block when stopOnBlock is false', () {
      fakeAsync((FakeAsync async) {
        final SentinelMonitor monitor = monitorWith(stopOnBlock: false);

        monitor.start();
        checks.add(reportWith(<DeviceThreat>{DeviceThreat.frida}));
        async.flushMicrotasks();

        expect(monitor.isRunning, isTrue);
      });
    });

    test('start is idempotent and stop cancels the checks', () async {
      final SentinelMonitor monitor = monitorWith();

      monitor.start();
      monitor.start();
      verify(() => sentinel.watch(interval: any(named: 'interval'))).called(1);

      await monitor.stop();
      expect(monitor.isRunning, isFalse);
      expect(checks.hasListener, isFalse);
    });

    test('a disposed monitor cannot be restarted', () async {
      final SentinelMonitor monitor = monitorWith();
      await monitor.dispose();

      monitor.start();

      expect(monitor.isRunning, isFalse);
      verifyNever(() => sentinel.watch(interval: any(named: 'interval')));
    });
  });
}
