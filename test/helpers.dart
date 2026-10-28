import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:mocktail/mocktail.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockDeviceSentinelPlatform extends Mock
    with MockPlatformInterfaceMixin
    implements DeviceSentinelPlatform {}

class MockDeviceSentinel extends Mock implements DeviceSentinel {}

class MockSentinelMonitor extends Mock implements SentinelMonitor {}

final DateTime fixedTime = DateTime.utc(2026, 1, 1, 12);

DeviceSecurityReport reportWith(
  Set<DeviceThreat> threats, {
  List<String> signals = const <String>[],
}) => DeviceSecurityReport(
  threats: threats,
  checkedAt: fixedTime,
  signals: signals,
);

/// A native-shaped reply: every native threat key present, `true` for
/// [threats].
Map<Object?, Object?> nativeReply(
  String nonce, {
  Set<DeviceThreat> threats = const <DeviceThreat>{},
  List<String> signals = const <String>[],
}) => <Object?, Object?>{
  'nonce': nonce,
  for (final DeviceThreat threat in DeviceThreat.values)
    if (threat != DeviceThreat.channelMismatch &&
        threat != DeviceThreat.checkFailed)
      threat.name: threats.contains(threat),
  'signals': signals,
};
