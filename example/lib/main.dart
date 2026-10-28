import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'report_screen.dart';

/// Replace with your own release identities. Empty lists skip the tamper
/// check, which is what this example wants: it is signed with a debug key.
const SentinelConfig _config = SentinelConfig(
  androidSigningCertSha256: <String>[],
  iosBundleIds: <String>[],
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final DeviceSentinel sentinel = DeviceSentinel(config: _config);

  // The host owns the policy. Typical shape: block in release, report in
  // debug/profile. A flavor check (e.g. "only production blocks") would go
  // into the `release:` argument.
  final SentinelPolicy policy = SentinelPolicy.forBuildMode(
    release: SentinelPolicy.strict,
  );

  // Boot-time gate: one check before the app UI exists.
  final DeviceSecurityReport bootReport = await sentinel.checkDevice();

  runApp(
    ExampleApp(
      sentinel: sentinel,
      monitor: SentinelMonitor(
        sentinel: sentinel,
        policy: policy,
        interval: const Duration(seconds: 15),
      ),
      bootReport: bootReport,
    ),
  );
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({
    super.key,
    required this.sentinel,
    required this.monitor,
    required this.bootReport,
  });

  final DeviceSentinel sentinel;
  final SentinelMonitor monitor;
  final DeviceSecurityReport bootReport;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'device_sentinel_security',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      builder: (BuildContext context, Widget? child) => SentinelGuard(
        monitor: monitor,
        initialReport: bootReport,
        blockedBuilder: (BuildContext context, SentinelViolation violation) =>
            SentinelBlockedView(
              violation: violation,
              // iOS ignores SystemNavigator.pop (apps may not quit
              // themselves), so the close button is only offered on Android.
              onClose: defaultTargetPlatform == TargetPlatform.android
                  ? SystemNavigator.pop
                  : null,
            ),
        child: child!,
      ),
      home: ReportScreen(
        sentinel: sentinel,
        monitor: monitor,
        initialReport: bootReport,
      ),
    );
  }
}
