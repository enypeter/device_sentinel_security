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
    when(() => monitor.policy).thenReturn(SentinelPolicy.instrumentationOnly);
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

  Future<void> pumpGuard(
    WidgetTester tester, {
    DeviceSecurityReport? initialReport,
    SentinelBlockedBuilder? blockedBuilder,
    ValueChanged<SentinelViolation>? onViolation,
  }) => tester.pumpWidget(
    MaterialApp(
      builder: (BuildContext context, Widget? child) => SentinelGuard(
        monitor: monitor,
        initialReport: initialReport,
        blockedBuilder: blockedBuilder,
        onViolation: onViolation,
        child: child!,
      ),
      home: const Scaffold(body: Text('app content')),
    ),
  );

  SentinelViolation violation(
    SentinelResponse response,
    Set<DeviceThreat> threats,
  ) => SentinelViolation(
    response: response,
    threats: threats,
    report: reportWith(threats),
  );

  testWidgets('shows the app and starts the monitor when all is clean', (
    WidgetTester tester,
  ) async {
    await pumpGuard(tester, initialReport: reportWith(const <DeviceThreat>{}));

    expect(find.text('app content'), findsOneWidget);
    verify(() => monitor.start()).called(1);
  });

  testWidgets('a blocking boot report replaces the app at once', (
    WidgetTester tester,
  ) async {
    await pumpGuard(
      tester,
      initialReport: reportWith(<DeviceThreat>{DeviceThreat.frida}),
    );

    expect(find.text('app content'), findsNothing);
    expect(find.text('Security check failed'), findsOneWidget);
    expect(find.text('(frida)'), findsOneWidget);
    // Nothing left to monitor once blocked.
    verifyNever(() => monitor.start());
  });

  testWidgets('a warning overlays a dismissible banner', (
    WidgetTester tester,
  ) async {
    await pumpGuard(
      tester,
      initialReport: reportWith(<DeviceThreat>{DeviceThreat.emulator}),
    );

    expect(find.text('app content'), findsOneWidget);
    expect(find.text('Security warning: emulator'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.close));
    await tester.pump();
    expect(find.text('Security warning: emulator'), findsNothing);
  });

  testWidgets('a block from the monitor replaces the app', (
    WidgetTester tester,
  ) async {
    final List<SentinelViolation> seen = <SentinelViolation>[];
    await pumpGuard(tester, onViolation: seen.add);

    violations.add(
      violation(SentinelResponse.block, <DeviceThreat>{DeviceThreat.rooted}),
    );
    await tester.pump();

    expect(find.text('app content'), findsNothing);
    expect(find.text('(rooted)'), findsOneWidget);
    expect(seen.single.response, SentinelResponse.block);
  });

  testWidgets('once blocked, later warnings are ignored', (
    WidgetTester tester,
  ) async {
    final List<SentinelViolation> seen = <SentinelViolation>[];
    await pumpGuard(tester, onViolation: seen.add);

    violations
      ..add(
        violation(SentinelResponse.block, <DeviceThreat>{DeviceThreat.frida}),
      )
      ..add(
        violation(SentinelResponse.warn, <DeviceThreat>{DeviceThreat.emulator}),
      );
    await tester.pump();

    expect(seen, hasLength(1));
    expect(find.textContaining('Security warning'), findsNothing);
  });

  testWidgets('the host can replace the blocked view', (
    WidgetTester tester,
  ) async {
    await pumpGuard(
      tester,
      initialReport: reportWith(<DeviceThreat>{DeviceThreat.frida}),
      blockedBuilder: (BuildContext context, SentinelViolation v) =>
          const Text('custom block'),
    );

    expect(find.text('custom block'), findsOneWidget);
  });

  testWidgets('the default blocked view has no close button unless asked', (
    WidgetTester tester,
  ) async {
    bool closed = false;
    await tester.pumpWidget(
      MaterialApp(
        home: SentinelBlockedView(
          violation: violation(SentinelResponse.block, <DeviceThreat>{
            DeviceThreat.tampered,
          }),
          onClose: () => closed = true,
        ),
      ),
    );

    await tester.tap(find.text('Close'));
    expect(closed, isTrue);

    await tester.pumpWidget(
      MaterialApp(
        home: SentinelBlockedView(
          violation: violation(SentinelResponse.block, <DeviceThreat>{
            DeviceThreat.tampered,
          }),
        ),
      ),
    );
    expect(find.text('Close'), findsNothing);
  });

  testWidgets('stops the monitor when removed', (WidgetTester tester) async {
    await pumpGuard(tester);
    await tester.pumpWidget(const SizedBox());

    verify(() => monitor.stop()).called(1);
  });
}
