import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'method_channel_device_sentinel.dart';

/// The transport between Dart and the native checks.
///
/// Replace [instance] only to support another platform; tests should pass a
/// fake to `DeviceSentinel(platform: …)` instead.
abstract class DeviceSentinelPlatform extends PlatformInterface {
  DeviceSentinelPlatform() : super(token: _token);

  static final Object _token = Object();

  static DeviceSentinelPlatform _instance = MethodChannelDeviceSentinel();

  /// The implementation used when none is passed to `DeviceSentinel`.
  static DeviceSentinelPlatform get instance => _instance;

  static set instance(DeviceSentinelPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Runs every native check once and returns the raw reply.
  ///
  /// [arguments] carries the request `nonce` and the `SentinelConfig`
  /// identities; the reply must echo the nonce and hold one boolean per
  /// `DeviceThreat` name it checked, plus an optional `signals` list.
  Future<Map<Object?, Object?>> checkDevice(Map<String, Object> arguments);
}
