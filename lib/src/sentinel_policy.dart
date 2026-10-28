import 'package:flutter/foundation.dart';

import 'device_security_report.dart';
import 'device_threat.dart';

/// What the host should do about a report.
enum SentinelResponse {
  /// Stop the user here — typically a full-screen blocked view.
  block,

  /// Let the user continue but surface it — a banner, a log, telemetry.
  warn,

  /// Nothing the policy cares about was raised.
  ignore,
}

/// Which threats block and which only warn. The plugin never decides this;
/// the host passes a policy, usually picked per build type and flavor.
@immutable
class SentinelPolicy {
  const SentinelPolicy({
    this.block = const <DeviceThreat>{},
    this.warn = const <DeviceThreat>{},
  });

  /// Threats that should stop the user.
  final Set<DeviceThreat> block;

  /// Threats that should only be surfaced. A threat in both sets blocks.
  final Set<DeviceThreat> warn;

  /// Blocks on everything that indicates a compromised or analysed device.
  /// Never blocks on [DeviceThreat.debuggableBuild] or
  /// [DeviceThreat.checkFailed].
  static const SentinelPolicy strict = SentinelPolicy(
    block: <DeviceThreat>{
      DeviceThreat.emulator,
      DeviceThreat.rooted,
      DeviceThreat.jailbroken,
      DeviceThreat.debuggerAttached,
      DeviceThreat.frida,
      DeviceThreat.hookingFramework,
      DeviceThreat.reverseEngineeringTools,
      DeviceThreat.tampered,
      DeviceThreat.channelMismatch,
    },
    warn: <DeviceThreat>{DeviceThreat.checkFailed},
  );

  /// Blocks only on live instrumentation; warns on the rest. Suits QA builds
  /// that must run on emulators and rooted test devices.
  static const SentinelPolicy instrumentationOnly = SentinelPolicy(
    block: <DeviceThreat>{
      DeviceThreat.frida,
      DeviceThreat.hookingFramework,
      DeviceThreat.channelMismatch,
    },
    warn: <DeviceThreat>{
      DeviceThreat.emulator,
      DeviceThreat.rooted,
      DeviceThreat.jailbroken,
      DeviceThreat.debuggerAttached,
      DeviceThreat.reverseEngineeringTools,
      DeviceThreat.tampered,
      DeviceThreat.checkFailed,
    },
  );

  /// Never blocks; warns on everything except [DeviceThreat.debuggableBuild]
  /// and [DeviceThreat.debuggerAttached], which every debug session raises.
  static const SentinelPolicy reportOnly = SentinelPolicy(
    warn: <DeviceThreat>{
      DeviceThreat.emulator,
      DeviceThreat.rooted,
      DeviceThreat.jailbroken,
      DeviceThreat.frida,
      DeviceThreat.hookingFramework,
      DeviceThreat.reverseEngineeringTools,
      DeviceThreat.tampered,
      DeviceThreat.channelMismatch,
      DeviceThreat.checkFailed,
    },
  );

  /// Ignores everything — for builds where the host wants telemetry only.
  static const SentinelPolicy off = SentinelPolicy();

  /// Picks a policy from the Flutter build mode. Flavor-based choices (for
  /// example "only the production flavor blocks") are the host's: pass the
  /// result of that decision as [release].
  static SentinelPolicy forBuildMode({
    required SentinelPolicy release,
    SentinelPolicy? profile,
    SentinelPolicy debug = reportOnly,
  }) => selectForBuildMode(
    isRelease: kReleaseMode,
    isProfile: kProfileMode,
    release: release,
    profile: profile,
    debug: debug,
  );

  /// [forBuildMode] with the build mode passed in, for tests.
  @visibleForTesting
  static SentinelPolicy selectForBuildMode({
    required bool isRelease,
    required bool isProfile,
    required SentinelPolicy release,
    SentinelPolicy? profile,
    SentinelPolicy debug = reportOnly,
  }) {
    if (isRelease) return release;
    if (isProfile) return profile ?? debug;
    return debug;
  }

  /// The raised threats this policy blocks on.
  Set<DeviceThreat> blocking(DeviceSecurityReport report) =>
      report.threats.intersection(block);

  /// The raised threats this policy only warns on.
  Set<DeviceThreat> warning(DeviceSecurityReport report) =>
      report.threats.intersection(warn).difference(block);

  /// The strongest response [report] calls for.
  SentinelResponse responseTo(DeviceSecurityReport report) {
    if (blocking(report).isNotEmpty) return SentinelResponse.block;
    if (warning(report).isNotEmpty) return SentinelResponse.warn;
    return SentinelResponse.ignore;
  }

  /// A copy with [block] and [warn] adjusted.
  SentinelPolicy copyWith({
    Set<DeviceThreat>? block,
    Set<DeviceThreat>? warn,
  }) => SentinelPolicy(block: block ?? this.block, warn: warn ?? this.warn);

  @override
  bool operator ==(Object other) =>
      other is SentinelPolicy &&
      setEquals(other.block, block) &&
      setEquals(other.warn, warn);

  @override
  int get hashCode => Object.hash(
    Object.hashAllUnordered(block),
    Object.hashAllUnordered(warn),
  );
}
