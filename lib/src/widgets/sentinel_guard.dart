import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../device_security_report.dart';
import '../device_threat.dart';
import '../sentinel_monitor.dart';
import '../sentinel_policy.dart';
import 'sentinel_views.dart';

/// Builds the view shown once a violation blocks.
typedef SentinelBlockedBuilder =
    Widget Function(BuildContext context, SentinelViolation violation);

/// Builds the overlay shown for a warning; call `dismiss` to hide it.
typedef SentinelWarningBuilder =
    Widget Function(
      BuildContext context,
      SentinelViolation violation,
      VoidCallback dismiss,
    );

/// Optional UI glue: shows [child] until [monitor] reports a violation, then
/// swaps in a blocked view or overlays a warning banner.
///
/// Mount it below `MaterialApp` so the default views get a theme and
/// directionality:
///
/// ```dart
/// MaterialApp(
///   builder: (context, child) => SentinelGuard(monitor: monitor, child: child!),
/// )
/// ```
///
/// Everything visual is replaceable through [blockedBuilder] and
/// [warningBuilder]; skip this widget entirely and listen to
/// [SentinelMonitor.violations] yourself for full control.
class SentinelGuard extends StatefulWidget {
  const SentinelGuard({
    super.key,
    required this.monitor,
    required this.child,
    this.initialReport,
    this.blockedBuilder,
    this.warningBuilder,
    this.onViolation,
    this.manageMonitor = true,
  });

  final SentinelMonitor monitor;
  final Widget child;

  /// A boot-time report to apply before the first monitor tick. Evaluated with
  /// [SentinelPolicy.responseTo]: any blocking threat blocks at once.
  final DeviceSecurityReport? initialReport;

  final SentinelBlockedBuilder? blockedBuilder;
  final SentinelWarningBuilder? warningBuilder;

  /// Called for every violation, before the UI reacts — the place for
  /// telemetry. For [initialReport] it runs after the first frame, so it may
  /// call `setState` on an ancestor.
  final ValueChanged<SentinelViolation>? onViolation;

  /// Start [monitor] when mounted and stop it when disposed. Set false when
  /// the host owns the monitor's lifecycle.
  final bool manageMonitor;

  @override
  State<SentinelGuard> createState() => _SentinelGuardState();
}

class _SentinelGuardState extends State<SentinelGuard> {
  StreamSubscription<SentinelViolation>? _violationSubscription;
  StreamSubscription<DeviceSecurityReport>? _reportSubscription;

  /// The monitor this guard started, which is not necessarily
  /// `widget.monitor` once the host has passed a new one.
  SentinelMonitor? _started;
  SentinelViolation? _blocked;
  SentinelViolation? _warning;

  /// Threats the user has dismissed. The monitor re-reports a standing
  /// warning on every tick; it should not come back until something new is
  /// raised, or the threat clears and later returns.
  Set<DeviceThreat> _dismissed = const <DeviceThreat>{};

  @override
  void initState() {
    super.initState();
    final DeviceSecurityReport? initial = widget.initialReport;
    final SentinelViolation? boot = initial == null
        ? null
        : _violationFor(initial);
    if (boot != null) {
      _record(boot);
      // The tree is still building here, so a callback that calls setState
      // on an ancestor would throw; let it run once the frame is done.
      WidgetsBinding.instance.addPostFrameCallback(
        (_) => widget.onViolation?.call(boot),
      );
    }
    _attach();
  }

  @override
  void didUpdateWidget(SentinelGuard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.monitor, widget.monitor) ||
        oldWidget.manageMonitor != widget.manageMonitor) {
      _detach();
      _attach();
    }
  }

  @override
  void dispose() {
    _detach();
    super.dispose();
  }

  void _attach() {
    final SentinelMonitor monitor = widget.monitor;
    // A block lives in the monitor, not only in this State, so a guard that
    // is remounted after a block stays blocked.
    _blocked ??= monitor.blockedBy;
    _violationSubscription = monitor.violations.listen(_onViolation);
    _reportSubscription = monitor.reports.listen(_onReport);
    if (widget.manageMonitor && _blocked == null) {
      monitor.start();
      _started = monitor;
    }
  }

  void _detach() {
    unawaited(_violationSubscription?.cancel());
    unawaited(_reportSubscription?.cancel());
    _violationSubscription = null;
    _reportSubscription = null;
    final SentinelMonitor? started = _started;
    _started = null;
    if (started != null) unawaited(started.stop());
  }

  SentinelViolation? _violationFor(DeviceSecurityReport report) {
    final SentinelPolicy policy = widget.monitor.policy;
    return switch (policy.responseTo(report)) {
      SentinelResponse.block => SentinelViolation(
        response: SentinelResponse.block,
        threats: policy.blocking(report),
        report: report,
      ),
      SentinelResponse.warn => SentinelViolation(
        response: SentinelResponse.warn,
        threats: policy.warning(report),
        report: report,
      ),
      SentinelResponse.ignore => null,
    };
  }

  void _record(SentinelViolation violation) {
    if (violation.response == SentinelResponse.block) {
      _blocked = violation;
      _warning = null;
    } else if (!_dismissed.containsAll(violation.threats)) {
      _warning = violation;
    }
  }

  void _onViolation(SentinelViolation violation) {
    if (_blocked != null || !mounted) return;
    widget.onViolation?.call(violation);
    setState(() => _record(violation));
  }

  /// The monitor emits no violation for a report its policy ignores, so the
  /// report stream is the only way to learn that a warned-about threat has
  /// gone (a debugger detached, a one-off timeout).
  void _onReport(DeviceSecurityReport report) {
    if (_blocked != null || !mounted) return;
    if (_warning == null && _dismissed.isEmpty) return;
    if (widget.monitor.policy.responseTo(report) != SentinelResponse.ignore) {
      return;
    }
    setState(() {
      _warning = null;
      _dismissed = const <DeviceThreat>{};
    });
  }

  void _dismissWarning() => setState(() {
    _dismissed = <DeviceThreat>{..._dismissed, ...?_warning?.threats};
    _warning = null;
  });

  /// The banner plus the status-bar area above it, painted with the theme
  /// surface so the system clock and icons stay readable.
  Widget _statusBarStrip(BuildContext context, SentinelViolation warning) {
    final Color surface = Theme.of(context).colorScheme.surface;
    final bool lightSurface =
        ThemeData.estimateBrightnessForColor(surface) == Brightness.light;
    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: lightSurface
          ? SystemUiOverlayStyle.dark
          : SystemUiOverlayStyle.light,
      child: ColoredBox(
        color: surface,
        child: SafeArea(
          bottom: false,
          child:
              widget.warningBuilder?.call(context, warning, _dismissWarning) ??
              SentinelWarningBanner(
                violation: warning,
                onDismiss: _dismissWarning,
              ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final SentinelViolation? blocked = _blocked;
    if (blocked != null) {
      return widget.blockedBuilder?.call(context, blocked) ??
          SentinelBlockedView(violation: blocked);
    }

    // The banner takes its own row above the app instead of floating over
    // it, so it never covers an app bar. The tree keeps the same shape with
    // or without a banner, so the app below is never rebuilt from scratch.
    final SentinelViolation? warning = _warning;
    return Column(
      children: <Widget>[
        if (warning != null) _statusBarStrip(context, warning),
        Expanded(
          child: MediaQuery.removePadding(
            context: context,
            removeTop: warning != null,
            child: widget.child,
          ),
        ),
      ],
    );
  }
}
