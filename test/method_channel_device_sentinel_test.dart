import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final MethodChannelDeviceSentinel platform = MethodChannelDeviceSentinel();
  final List<MethodCall> calls = <MethodCall>[];

  void reply(Object? Function(MethodCall call) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(platform.methodChannel, (
          MethodCall call,
        ) async {
          calls.add(call);
          return handler(call);
        });
  }

  tearDown(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(platform.methodChannel, null);
  });

  test('is the default platform instance', () {
    expect(DeviceSentinelPlatform.instance, isA<MethodChannelDeviceSentinel>());
  });

  test('invokes checkDevice with the arguments and returns the map', () async {
    reply((_) => <String, Object>{'nonce': 'n', 'emulator': true});

    final Map<Object?, Object?> result = await platform.checkDevice(
      <String, Object>{'nonce': 'n'},
    );

    expect(calls.single.method, 'checkDevice');
    expect(calls.single.arguments, <String, Object>{'nonce': 'n'});
    expect(result, <Object?, Object?>{'nonce': 'n', 'emulator': true});
  });

  test('a null reply is a PlatformException, not a silent pass', () {
    reply((_) => null);

    expect(
      platform.checkDevice(<String, Object>{}),
      throwsA(
        isA<PlatformException>().having(
          (PlatformException e) => e.code,
          'code',
          'empty_reply',
        ),
      ),
    );
  });

  test('a native error surfaces as PlatformException', () {
    reply((_) => throw PlatformException(code: 'check_failed'));

    expect(
      platform.checkDevice(<String, Object>{}),
      throwsA(isA<PlatformException>()),
    );
  });
}
