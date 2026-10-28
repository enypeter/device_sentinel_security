import 'dart:async';

import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:fake_async/fake_async.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';

import 'helpers.dart';

void main() {
  late MockDeviceSentinelPlatform platform;

  setUpAll(() => registerFallbackValue(<String, Object>{}));

  setUp(() => platform = MockDeviceSentinelPlatform());

  DeviceSentinel sentinelWith({
    SentinelConfig config = const SentinelConfig(),
    Duration timeout = const Duration(seconds: 10),
  }) => DeviceSentinel(
    config: config,
    platform: platform,
    timeout: timeout,
    nonceFactory: () => 'nonce-1',
    clock: () => fixedTime,
  );

  group('checkDevice', () {
    test('sends the nonce and the config identities', () async {
      when(
        () => platform.checkDevice(any()),
      ).thenAnswer((_) async => nativeReply('nonce-1'));

      await sentinelWith(
        config: SentinelConfig(
          androidSigningCertSha256: <String>['AA:BB' * 16],
          iosBundleIds: const <String>['com.example.app'],
        ),
      ).checkDevice();

      verify(
        () => platform.checkDevice(<String, Object>{
          'nonce': 'nonce-1',
          'androidSigningCertSha256': <String>['aabb' * 16],
          'iosBundleIds': <String>['com.example.app'],
        }),
      ).called(1);
    });

    test('a fingerprint that is not SHA-256 fails loudly in debug', () {
      expect(
        () => DeviceSentinel(
          config: SentinelConfig(
            androidSigningCertSha256: <String>['CD:' * 19 + 'CD'],
          ),
          platform: platform,
        ),
        throwsAssertionError,
      );
    });

    test('returns the parsed report when the nonce is echoed', () async {
      when(() => platform.checkDevice(any())).thenAnswer(
        (_) async => nativeReply(
          'nonce-1',
          threats: <DeviceThreat>{DeviceThreat.jailbroken},
          signals: <String>['jailbreak.path'],
        ),
      );

      final DeviceSecurityReport report = await sentinelWith().checkDevice();

      expect(
        report,
        reportWith(
          <DeviceThreat>{DeviceThreat.jailbroken},
          signals: <String>['jailbreak.path'],
        ),
      );
    });

    test('a reply with another nonce adds channelMismatch', () async {
      when(
        () => platform.checkDevice(any()),
      ).thenAnswer((_) async => nativeReply('replayed-nonce'));

      final DeviceSecurityReport report = await sentinelWith().checkDevice();

      expect(report.threats, <DeviceThreat>{DeviceThreat.channelMismatch});
      expect(report.signals, contains('channel.nonce'));
    });

    test('a reply without a nonce adds channelMismatch', () async {
      when(
        () => platform.checkDevice(any()),
      ).thenAnswer((_) async => <Object?, Object?>{'emulator': true});

      final DeviceSecurityReport report = await sentinelWith().checkDevice();

      expect(report.threats, <DeviceThreat>{
        DeviceThreat.emulator,
        DeviceThreat.channelMismatch,
      });
    });

    test('a timeout becomes checkFailed instead of throwing', () {
      fakeAsync((FakeAsync async) {
        when(
          () => platform.checkDevice(any()),
        ).thenAnswer((_) => Completer<Map<Object?, Object?>>().future);

        DeviceSecurityReport? report;
        sentinelWith(
          timeout: const Duration(seconds: 2),
        ).checkDevice().then((DeviceSecurityReport r) => report = r);

        async.elapse(const Duration(seconds: 1));
        expect(report, isNull);
        async.elapse(const Duration(seconds: 1));

        expect(report!.threats, <DeviceThreat>{DeviceThreat.checkFailed});
        expect(report!.failure, 'timeout');
      });
    });

    test('a PlatformException becomes checkFailed with its code', () async {
      when(
        () => platform.checkDevice(any()),
      ).thenThrow(PlatformException(code: 'check_failed'));

      final DeviceSecurityReport report = await sentinelWith().checkDevice();

      expect(report.threats, <DeviceThreat>{DeviceThreat.checkFailed});
      expect(report.failure, 'platform_error:check_failed');
    });

    test('a missing native plugin becomes checkFailed', () async {
      when(
        () => platform.checkDevice(any()),
      ).thenThrow(MissingPluginException());

      final DeviceSecurityReport report = await sentinelWith().checkDevice();

      expect(report.failure, 'missing_plugin');
    });

    test('any other error becomes checkFailed', () async {
      when(() => platform.checkDevice(any())).thenThrow(StateError('boom'));

      final DeviceSecurityReport report = await sentinelWith().checkDevice();

      expect(report.failure, 'error:StateError');
    });
  });

  group('watch', () {
    test('checks at once, then on every interval', () {
      fakeAsync((FakeAsync async) {
        when(
          () => platform.checkDevice(any()),
        ).thenAnswer((_) async => nativeReply('nonce-1'));
        final List<DeviceSecurityReport> reports = <DeviceSecurityReport>[];

        final StreamSubscription<DeviceSecurityReport> subscription =
            sentinelWith()
                .watch(interval: const Duration(seconds: 30))
                .listen(reports.add);
        async.flushMicrotasks();
        expect(reports, hasLength(1));

        async.elapse(const Duration(seconds: 60));
        expect(reports, hasLength(3));

        subscription.cancel();
        async.elapse(const Duration(seconds: 60));
        expect(reports, hasLength(3));
        verify(() => platform.checkDevice(any())).called(3);
      });
    });

    test('after a timeout, reports stalled instead of queueing natively', () {
      fakeAsync((FakeAsync async) {
        final Completer<Map<Object?, Object?>> stuck =
            Completer<Map<Object?, Object?>>();
        int calls = 0;
        when(() => platform.checkDevice(any())).thenAnswer((_) {
          calls++;
          return calls == 1
              ? stuck.future
              : Future.value(nativeReply('nonce-1'));
        });
        final List<DeviceSecurityReport> reports = <DeviceSecurityReport>[];

        sentinelWith(
          timeout: const Duration(seconds: 2),
        ).watch(interval: const Duration(seconds: 5)).listen(reports.add);
        async.elapse(const Duration(seconds: 2));
        expect(reports.single.failure, 'timeout');

        // The first native call is still running: the next tick must not
        // queue a second one behind it.
        async.elapse(const Duration(seconds: 3));
        expect(calls, 1);
        expect(reports.last.failure, 'stalled');
        expect(reports.last.has(DeviceThreat.checkFailed), isTrue);

        // Once the native side answers, checks resume.
        stuck.complete(nativeReply('nonce-1'));
        async.elapse(const Duration(seconds: 5));
        expect(calls, 2);
        expect(reports.last.isClean, isTrue);
      });
    });

    test('skips ticks while a check is still running', () {
      fakeAsync((FakeAsync async) {
        final Completer<Map<Object?, Object?>> slow =
            Completer<Map<Object?, Object?>>();
        when(() => platform.checkDevice(any())).thenAnswer((_) => slow.future);
        final List<DeviceSecurityReport> reports = <DeviceSecurityReport>[];

        sentinelWith(
          timeout: const Duration(minutes: 10),
        ).watch(interval: const Duration(seconds: 1)).listen(reports.add);
        async.elapse(const Duration(seconds: 5));

        verify(() => platform.checkDevice(any())).called(1);
        slow.complete(nativeReply('nonce-1'));
        async.flushMicrotasks();
        expect(reports, hasLength(1));
      });
    });
  });
}
