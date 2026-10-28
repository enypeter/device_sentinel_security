import 'dart:async';
import 'dart:math';

import 'package:flutter/services.dart';

import 'device_security_report.dart';
import 'device_threat.dart';
import 'platform/device_sentinel_platform.dart';
import 'sentinel_config.dart';

/// Runs the native device checks.
///
/// ```dart
/// final sentinel = DeviceSentinel(config: const SentinelConfig(
///   androidSigningCertSha256: ['AB:CD:…'],
///   iosBundleIds: ['com.example.app'],
/// ));
/// final report = await sentinel.checkDevice();
/// ```
class DeviceSentinel {
  DeviceSentinel({
    this.config = const SentinelConfig(),
    DeviceSentinelPlatform? platform,
    this.timeout = const Duration(seconds: 10),
    String Function()? nonceFactory,
    DateTime Function()? clock,
  }) : assert(
         config.invalidAndroidFingerprints.isEmpty,
         'SentinelConfig.androidSigningCertSha256 holds entries that are not '
         'SHA-256 fingerprints, so the Android signature check is skipped: '
         '${config.invalidAndroidFingerprints}',
       ),
       _platform = platform ?? DeviceSentinelPlatform.instance,
       _nonceFactory = nonceFactory ?? _secureNonce,
       _clock = clock ?? DateTime.now;

  /// Identities the tamper check compares against.
  final SentinelConfig config;

  /// How long one check may take before it is reported as
  /// [DeviceThreat.checkFailed].
  final Duration timeout;

  final DeviceSentinelPlatform _platform;
  final String Function() _nonceFactory;
  final DateTime Function() _clock;

  /// Native calls Dart gave up on after [timeout] that have still not
  /// answered. The native side keeps running them on its serial queue, so
  /// anything sent now would wait behind them.
  int _stalledNativeCalls = 0;

  /// Runs every check once. Never throws: a failure, timeout or missing plugin
  /// becomes a report holding [DeviceThreat.checkFailed].
  Future<DeviceSecurityReport> checkDevice() async {
    final String nonce = _nonceFactory();
    final Map<Object?, Object?> reply;
    bool timedOut = false;
    try {
      final Future<Map<Object?, Object?>> call = _platform.checkDevice(
        <String, Object>{'nonce': nonce, ...config.toChannelArguments()},
      );
      unawaited(
        call.then<void>((_) {}, onError: (Object _) {}).whenComplete(() {
          if (timedOut) _stalledNativeCalls--;
        }),
      );
      reply = await call.timeout(timeout);
    } on TimeoutException {
      timedOut = true;
      _stalledNativeCalls++;
      return DeviceSecurityReport.failed('timeout', checkedAt: _clock());
    } on MissingPluginException {
      return DeviceSecurityReport.failed('missing_plugin', checkedAt: _clock());
    } on PlatformException catch (error) {
      return DeviceSecurityReport.failed(
        'platform_error:${error.code}',
        checkedAt: _clock(),
      );
    } catch (error) {
      return DeviceSecurityReport.failed(
        'error:${error.runtimeType}',
        checkedAt: _clock(),
      );
    }

    final DeviceSecurityReport report = DeviceSecurityReport.fromChannelReply(
      reply,
      checkedAt: _clock(),
    );
    // A reply that does not echo this request's nonce was not produced for
    // this request. Keep whatever it claimed, but mark the channel itself.
    final bool echoed = reply['nonce'] == nonce;
    final bool configValid = config.invalidAndroidFingerprints.isEmpty;
    if (echoed && configValid) return report;
    return DeviceSecurityReport(
      threats: <DeviceThreat>{
        ...report.threats,
        if (!echoed) DeviceThreat.channelMismatch,
      },
      signals: <String>[
        ...report.signals,
        if (!echoed) 'channel.nonce',
        if (!configValid) 'config.invalid_fingerprint',
      ],
      checkedAt: report.checkedAt,
    );
  }

  /// Checks now, then every [interval], for as long as the stream is listened
  /// to. A tick that arrives while the previous check is still running is
  /// skipped rather than queued, so slow devices never pile up checks.
  ///
  /// When a check has timed out but is still running natively, each tick
  /// reports [DeviceThreat.checkFailed] (`stalled`) instead of queueing
  /// another native call behind the stuck one.
  Stream<DeviceSecurityReport> watch({
    Duration interval = const Duration(seconds: 30),
  }) {
    assert(interval > Duration.zero, 'interval must be positive');
    late final StreamController<DeviceSecurityReport> controller;
    Timer? timer;
    bool inFlight = false;

    Future<void> tick() async {
      if (inFlight) return;
      if (_stalledNativeCalls > 0) {
        if (!controller.isClosed) {
          controller.add(
            DeviceSecurityReport.failed('stalled', checkedAt: _clock()),
          );
        }
        return;
      }
      inFlight = true;
      try {
        final DeviceSecurityReport report = await checkDevice();
        if (!controller.isClosed) controller.add(report);
      } finally {
        inFlight = false;
      }
    }

    controller = StreamController<DeviceSecurityReport>(
      onListen: () {
        unawaited(tick());
        timer = Timer.periodic(interval, (_) => unawaited(tick()));
      },
      onCancel: () {
        timer?.cancel();
        timer = null;
        return controller.close();
      },
    );
    return controller.stream;
  }

  static String _secureNonce() {
    final Random random = Random.secure();
    return List<String>.generate(
      16,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
  }
}
