import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'device_sentinel_platform.dart';

/// [DeviceSentinelPlatform] over a [MethodChannel].
///
/// Both native handlers run on a background task queue: the checks read files,
/// walk loaded images and query the package manager, which must never happen
/// on the platform (UI) thread.
class MethodChannelDeviceSentinel extends DeviceSentinelPlatform {
  /// The channel name shared with the Android and iOS plugins.
  static const String channelName = 'device_sentinel_security';

  @visibleForTesting
  final MethodChannel methodChannel = const MethodChannel(channelName);

  @override
  Future<Map<Object?, Object?>> checkDevice(
    Map<String, Object> arguments,
  ) async {
    final Map<Object?, Object?>? reply = await methodChannel
        .invokeMethod<Map<Object?, Object?>>('checkDevice', arguments);
    if (reply == null) {
      throw PlatformException(
        code: 'empty_reply',
        message: 'checkDevice returned no result',
      );
    }
    return reply;
  }
}
