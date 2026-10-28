import 'package:flutter/foundation.dart';

import 'device_threat.dart';

/// The outcome of one device check.
@immutable
class DeviceSecurityReport {
  DeviceSecurityReport({
    required Set<DeviceThreat> threats,
    required this.checkedAt,
    List<String> signals = const <String>[],
    this.failure,
  }) : threats = Set<DeviceThreat>.unmodifiable(threats),
       signals = List<String>.unmodifiable(signals);

  /// A report for a check that could not run. Carries only
  /// [DeviceThreat.checkFailed], never a guess at the other threats.
  factory DeviceSecurityReport.failed(String reason, {DateTime? checkedAt}) =>
      DeviceSecurityReport(
        threats: const <DeviceThreat>{DeviceThreat.checkFailed},
        checkedAt: checkedAt ?? DateTime.now(),
        failure: reason,
      );

  /// Parses the native reply. Unknown keys are ignored and missing keys read
  /// as "not detected", so a newer native side never breaks an older Dart one.
  factory DeviceSecurityReport.fromChannelReply(
    Map<Object?, Object?> reply, {
    required DateTime checkedAt,
  }) {
    final Set<DeviceThreat> threats = <DeviceThreat>{
      for (final DeviceThreat threat in DeviceThreat.values)
        if (reply[threat.name] == true) threat,
    };
    final Object? signals = reply['signals'];
    return DeviceSecurityReport(
      threats: threats,
      checkedAt: checkedAt,
      signals: signals is List
          ? signals.whereType<String>().toList()
          : const <String>[],
    );
  }

  /// Every threat this check raised.
  final Set<DeviceThreat> threats;

  /// Which probes fired, e.g. `root.path`, `frida.maps`, `tamper.signature`.
  ///
  /// Short fixed identifiers, never paths, package names or user data, so they
  /// are safe to send to analytics and are the first thing to look at when a
  /// legitimate device is flagged.
  final List<String> signals;

  /// When the check completed.
  final DateTime checkedAt;

  /// Why the check failed, when [threats] holds [DeviceThreat.checkFailed].
  final String? failure;

  /// True when no threat at all was raised.
  bool get isClean => threats.isEmpty;

  /// Whether [threat] was raised.
  bool has(DeviceThreat threat) => threats.contains(threat);

  /// Flat, PII-free attributes for analytics or crash reporting: one boolean
  /// per threat, the fired signals and the failure reason.
  Map<String, Object> toTelemetry() => <String, Object>{
    for (final DeviceThreat threat in DeviceThreat.values)
      'sentinel_${threat.name}': has(threat),
    'sentinel_signals': signals.join(','),
    'sentinel_failure': ?failure,
  };

  @override
  bool operator ==(Object other) =>
      other is DeviceSecurityReport &&
      setEquals(other.threats, threats) &&
      listEquals(other.signals, signals) &&
      other.checkedAt == checkedAt &&
      other.failure == failure;

  @override
  int get hashCode => Object.hash(
    Object.hashAllUnordered(threats),
    Object.hashAll(signals),
    checkedAt,
    failure,
  );

  @override
  String toString() =>
      'DeviceSecurityReport(threats: ${threats.map((DeviceThreat t) => t.name).join(', ')}, '
      'signals: ${signals.join(', ')}, checkedAt: $checkedAt'
      '${failure == null ? '' : ', failure: $failure'})';
}
