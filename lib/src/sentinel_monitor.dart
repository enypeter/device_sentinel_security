import 'dart:async';

import 'package:flutter/foundation.dart';

import 'device_security_report.dart';
import 'device_sentinel.dart';
import 'device_threat.dart';
import 'sentinel_policy.dart';

/// A report the policy did not [SentinelResponse.ignore].
@immutable
class SentinelViolation {
  const SentinelViolation({
    required this.response,
    required this.threats,
    required this.report,
    this.strikes = 0,
  });

  /// [SentinelResponse.block] or [SentinelResponse.warn].
  final SentinelResponse response;

  /// The threats that caused [response].
  final Set<DeviceThreat> threats;

  /// The full report, including threats the policy ignores.
  final DeviceSecurityReport report;

  /// Consecutive reports with a blocking threat, counting this one.
  final int strikes;

  @override
  String toString() =>
      'SentinelViolation(${response.name}: '
      '${threats.map((DeviceThreat t) => t.name).join(', ')}, strikes: $strikes)';
}

/// Re-checks the device on an interval and turns reports into violations.
///
/// A blocking threat in [blockImmediately] escalates to
/// [SentinelResponse.block] on first sight. Any other blocking threat is
/// reported as [SentinelResponse.warn] until it has been seen in
/// [strikesToBlock] consecutive checks, so one flaky probe cannot lock a user
/// out. A check without a blocking threat resets the count; a failed check
/// ([DeviceThreat.checkFailed]) is no evidence either way and leaves it as is.
class SentinelMonitor {
  SentinelMonitor({
    required this.sentinel,
    required this.policy,
    this.interval = const Duration(seconds: 30),
    this.strikesToBlock = 3,
    this.blockImmediately = defaultBlockImmediately,
    this.stopOnBlock = true,
  }) : assert(strikesToBlock > 0, 'strikesToBlock must be positive');

  /// Live instrumentation: no reason to wait for a second sighting.
  static const Set<DeviceThreat> defaultBlockImmediately = <DeviceThreat>{
    DeviceThreat.frida,
    DeviceThreat.hookingFramework,
    DeviceThreat.debuggerAttached,
    DeviceThreat.channelMismatch,
  };

  final DeviceSentinel sentinel;
  final SentinelPolicy policy;
  final Duration interval;
  final int strikesToBlock;
  final Set<DeviceThreat> blockImmediately;

  /// Stop checking once a block has been emitted; the host is expected to
  /// replace the UI at that point.
  final bool stopOnBlock;

  final StreamController<SentinelViolation> _violations =
      StreamController<SentinelViolation>.broadcast();
  final StreamController<DeviceSecurityReport> _reports =
      StreamController<DeviceSecurityReport>.broadcast();
  StreamSubscription<DeviceSecurityReport>? _subscription;
  DeviceSecurityReport? _lastReport;
  SentinelViolation? _blockedBy;
  int _strikes = 0;

  /// Every violation, as it happens.
  Stream<SentinelViolation> get violations => _violations.stream;

  /// Every report, clean or not — for telemetry.
  Stream<DeviceSecurityReport> get reports => _reports.stream;

  bool get isRunning => _subscription != null;

  /// Consecutive reports with a blocking threat.
  int get strikes => _strikes;

  DeviceSecurityReport? get lastReport => _lastReport;

  DateTime? get lastCheckAt => _lastReport?.checkedAt;

  /// The first violation this monitor escalated to [SentinelResponse.block].
  /// It is never cleared, so UI that is rebuilt or remounted after a block
  /// (see `SentinelGuard`) stays blocked instead of starting over.
  SentinelViolation? get blockedBy => _blockedBy;

  /// Starts checking: once now, then every [interval]. No-op when running,
  /// after [dispose], or once blocked when [stopOnBlock] is set.
  void start() {
    if (isRunning || _violations.isClosed) return;
    if (stopOnBlock && _blockedBy != null) return;
    _strikes = 0;
    _subscription = sentinel.watch(interval: interval).listen(_onReport);
  }

  /// Stops checking. Safe to call when not running.
  Future<void> stop() async {
    final StreamSubscription<DeviceSecurityReport>? subscription =
        _subscription;
    _subscription = null;
    await subscription?.cancel();
  }

  /// Stops and closes both streams. The monitor cannot be restarted.
  Future<void> dispose() async {
    await stop();
    await _violations.close();
    await _reports.close();
  }

  /// Applies the strike rules to [report] and returns the violation it
  /// produces, if any. Updates [strikes].
  @visibleForTesting
  SentinelViolation? evaluate(DeviceSecurityReport report) {
    final Set<DeviceThreat> blocking = policy.blocking(report);
    if (blocking.isNotEmpty) {
      _strikes++;
      final bool escalate =
          blocking.any(blockImmediately.contains) || _strikes >= strikesToBlock;
      return SentinelViolation(
        response: escalate ? SentinelResponse.block : SentinelResponse.warn,
        threats: blocking,
        report: report,
        strikes: _strikes,
      );
    }

    // A failed check saw nothing, so it neither adds a strike nor clears them:
    // otherwise a check that times out every other tick would keep a real
    // threat below strikesToBlock forever.
    if (!report.has(DeviceThreat.checkFailed)) _strikes = 0;
    final Set<DeviceThreat> warning = policy.warning(report);
    if (warning.isEmpty) return null;
    return SentinelViolation(
      response: SentinelResponse.warn,
      threats: warning,
      report: report,
    );
  }

  void _onReport(DeviceSecurityReport report) {
    _lastReport = report;
    if (!_reports.isClosed) _reports.add(report);

    final SentinelViolation? violation = evaluate(report);
    if (violation == null) return;
    final bool blocks = violation.response == SentinelResponse.block;
    if (blocks) _blockedBy ??= violation;
    if (!_violations.isClosed) _violations.add(violation);
    if (stopOnBlock && blocks) unawaited(stop());
  }
}
