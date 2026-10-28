import 'dart:async';

import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';

import 'helpers.dart';

void main() {
  late MockSentinelMonitor monitor;
  late StreamController<SentinelViolation> violations;
  late StreamController<DeviceSecurityReport> reports;

  setUp(() {
    monitor = MockSentinelMonitor();
    violations = StreamController<SentinelViolation>.broadcast();
    reports = StreamController<DeviceSecurityReport>.broadcast();
    when(() => monitor.policy).thenReturn(SentinelPolicy.reportOnly);
    when(() => monitor.violations).thenAnswer((_) => violations.stream);
    when(() => monitor.reports).thenAnswer((_) => reports.stream);
    when(() => monitor.blockedBy).thenReturn(null);
    when(() => monitor.start()).thenReturn(null);
    when(() => monitor.stop()).thenAnswer((_) async {});
  });

  tearDown(() async {
    await violations.close();
    await reports.close();
  });

  SentinelViolation warn(Set<DeviceThreat> threats) => SentinelViolation(
    response: SentinelResponse.warn,
    threats: threats,
    report: reportWith(threats),
  );

  Future<void> pumpApp(WidgetTester tester) => tester.pumpWidget(
    MaterialApp(
      builder: (BuildContext context, Widget? child) =>
          SentinelGuard(monitor: monitor, child: child!),
      home: Builder(
        builder: (BuildContext context) => Scaffold(
          appBar: AppBar(title: const Text('home')),
          body: TextButton(
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(
                builder: (_) =>
                    Scaffold(appBar: AppBar(title: const Text('second'))),
              ),
            ),
            child: const Text('open'),
          ),
        ),
      ),
    ),
  );

  testWidgets('a runtime warning keeps the navigation stack', (
    WidgetTester tester,
  ) async {
    await pumpApp(tester);
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    expect(find.text('second'), findsOneWidget);

    violations.add(warn(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();

    expect(find.text('Security warning: emulator'), findsOneWidget);
    expect(find.text('second'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.close));
    await tester.pumpAndSettle();
    expect(find.text('second'), findsOneWidget);
  });

  testWidgets('the banner sits above the app bar instead of covering it', (
    WidgetTester tester,
  ) async {
    await pumpApp(tester);
    violations.add(warn(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();

    final Rect banner = tester.getRect(find.byType(SentinelWarningBanner));
    final Rect appBar = tester.getRect(find.byType(AppBar));
    expect(appBar.top, greaterThanOrEqualTo(banner.bottom));
  });

  testWidgets('a dismissed warning stays dismissed for the same threats', (
    WidgetTester tester,
  ) async {
    await pumpApp(tester);
    violations.add(warn(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Icons.close));
    await tester.pumpAndSettle();

    violations.add(warn(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();
    expect(find.byType(SentinelWarningBanner), findsNothing);

    violations.add(
      warn(<DeviceThreat>{DeviceThreat.emulator, DeviceThreat.rooted}),
    );
    await tester.pumpAndSettle();
    expect(find.byType(SentinelWarningBanner), findsOneWidget);
  });

  testWidgets('a warning clears once a report shows the threat gone', (
    WidgetTester tester,
  ) async {
    await pumpApp(tester);
    violations.add(warn(<DeviceThreat>{DeviceThreat.debuggerAttached}));
    await tester.pumpAndSettle();
    expect(find.byType(SentinelWarningBanner), findsOneWidget);

    // The monitor emits no violation for a clean report; only the report
    // stream says the debugger is gone.
    reports.add(reportWith(const <DeviceThreat>{}));
    await tester.pumpAndSettle();
    expect(find.byType(SentinelWarningBanner), findsNothing);
  });

  testWidgets('a report the policy still warns on keeps the banner', (
    WidgetTester tester,
  ) async {
    await pumpApp(tester);
    violations.add(warn(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();

    reports.add(reportWith(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();
    expect(find.byType(SentinelWarningBanner), findsOneWidget);
  });

  testWidgets('a guard mounted after the monitor blocked stays blocked', (
    WidgetTester tester,
  ) async {
    when(() => monitor.blockedBy).thenReturn(
      SentinelViolation(
        response: SentinelResponse.block,
        threats: const <DeviceThreat>{DeviceThreat.frida},
        report: reportWith(<DeviceThreat>{DeviceThreat.frida}),
      ),
    );

    await pumpApp(tester);

    expect(find.byType(SentinelBlockedView), findsOneWidget);
    expect(find.text('home'), findsNothing);
    verifyNever(() => monitor.start());
  });

  testWidgets('a new monitor replaces the old one, and the right one stops', (
    WidgetTester tester,
  ) async {
    final MockSentinelMonitor next = MockSentinelMonitor();
    final StreamController<SentinelViolation> nextViolations =
        StreamController<SentinelViolation>.broadcast();
    addTearDown(nextViolations.close);
    when(() => next.policy).thenReturn(SentinelPolicy.reportOnly);
    when(() => next.violations).thenAnswer((_) => nextViolations.stream);
    when(() => next.reports).thenAnswer((_) => reports.stream);
    when(() => next.blockedBy).thenReturn(null);
    when(() => next.start()).thenReturn(null);
    when(() => next.stop()).thenAnswer((_) async {});

    Widget app(SentinelMonitor m) => MaterialApp(
      builder: (BuildContext context, Widget? child) =>
          SentinelGuard(monitor: m, child: child!),
      home: const Text('home'),
    );

    await tester.pumpWidget(app(monitor));
    await tester.pumpWidget(app(next));
    verify(() => monitor.stop()).called(1);
    verify(() => next.start()).called(1);

    nextViolations.add(warn(<DeviceThreat>{DeviceThreat.emulator}));
    await tester.pumpAndSettle();
    expect(find.byType(SentinelWarningBanner), findsOneWidget);

    await tester.pumpWidget(const SizedBox());
    verify(() => next.stop()).called(1);
    verifyNever(() => monitor.stop());
  });

  testWidgets('onViolation for the boot report may setState an ancestor', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(_Host(monitor: monitor));

    expect(tester.takeException(), isNull);
    await tester.pump();
    expect(find.text('seen: emulator'), findsOneWidget);
  });
}

/// Rebuilds itself from SentinelGuard.onViolation, as a host recording the
/// last violation in its own state would.
class _Host extends StatefulWidget {
  const _Host({required this.monitor});

  final SentinelMonitor monitor;

  @override
  State<_Host> createState() => _HostState();
}

class _HostState extends State<_Host> {
  String _seen = 'nothing';

  @override
  Widget build(BuildContext context) => MaterialApp(
    builder: (BuildContext context, Widget? child) => SentinelGuard(
      monitor: widget.monitor,
      initialReport: reportWith(<DeviceThreat>{DeviceThreat.emulator}),
      onViolation: (SentinelViolation v) =>
          setState(() => _seen = describeThreats(v.threats)),
      child: child!,
    ),
    home: Text('seen: $_seen'),
  );
}
