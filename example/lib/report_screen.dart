import 'dart:async';

import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter/material.dart';

/// The built-in policies, for previewing what each would do with a report.
enum PolicyChoice {
  strict('Strict', SentinelPolicy.strict),
  instrumentation('Instr.', SentinelPolicy.instrumentationOnly),
  report('Report', SentinelPolicy.reportOnly),
  off('Off', SentinelPolicy.off);

  const PolicyChoice(this.label, this.policy);

  final String label;
  final SentinelPolicy policy;
}

/// Shows the latest report, what each built-in policy would do with it, and
/// the runtime monitor's activity.
class ReportScreen extends StatefulWidget {
  const ReportScreen({
    super.key,
    required this.sentinel,
    required this.monitor,
    required this.initialReport,
  });

  final DeviceSentinel sentinel;
  final SentinelMonitor monitor;
  final DeviceSecurityReport initialReport;

  @override
  State<ReportScreen> createState() => _ReportScreenState();
}

class _ReportScreenState extends State<ReportScreen> {
  late DeviceSecurityReport _report = widget.initialReport;
  PolicyChoice _choice = PolicyChoice.strict;
  bool _checking = false;
  Duration? _lastDuration;
  int _monitorTicks = 0;
  SentinelViolation? _lastViolation;
  final List<StreamSubscription<Object>> _subscriptions =
      <StreamSubscription<Object>>[];

  @override
  void initState() {
    super.initState();
    _subscriptions
      ..add(
        widget.monitor.reports.listen(
          (DeviceSecurityReport report) => setState(() {
            _monitorTicks++;
            _report = report;
          }),
        ),
      )
      ..add(
        widget.monitor.violations.listen(
          (SentinelViolation violation) =>
              setState(() => _lastViolation = violation),
        ),
      );
  }

  @override
  void dispose() {
    for (final StreamSubscription<Object> subscription in _subscriptions) {
      unawaited(subscription.cancel());
    }
    super.dispose();
  }

  Future<void> _recheck() async {
    setState(() => _checking = true);
    final Stopwatch stopwatch = Stopwatch()..start();
    final DeviceSecurityReport report = await widget.sentinel.checkDevice();
    stopwatch.stop();
    if (!mounted) return;
    setState(() {
      _report = report;
      _lastDuration = stopwatch.elapsed;
      _checking = false;
    });
  }

  void _previewBlockedScreen(SentinelPolicy policy) {
    final SentinelViolation violation = SentinelViolation(
      response: SentinelResponse.block,
      threats: policy.blocking(_report),
      report: _report,
    );
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (BuildContext context) => Scaffold(
          appBar: AppBar(title: const Text('Blocked screen preview')),
          body: SentinelBlockedView(
            violation: violation,
            onClose: () => Navigator.of(context).pop(),
            closeLabel: 'Back',
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Device Sentinel')),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 96),
        children: <Widget>[
          ListTile(
            key: const Key('summary'),
            title: Text(
              _report.isClean ? 'No threats found' : 'Threats found',
              style: text.titleLarge,
            ),
            subtitle: Text(
              'Checked ${_formatTime(_report.checkedAt)}'
              '${_lastDuration == null ? '' : ' in ${_lastDuration!.inMilliseconds} ms'}'
              '${_report.failure == null ? '' : '\nFailure: ${_report.failure}'}',
            ),
          ),
          const _Header('Threats'),
          for (final DeviceThreat threat in DeviceThreat.values)
            ListTile(
              dense: true,
              leading: Icon(
                _report.has(threat) ? Icons.error : Icons.check_circle,
                color: _report.has(threat) ? Colors.red : Colors.green,
              ),
              title: Text(threat.name),
            ),
          const _Header('Signals (which probe fired)'),
          ListTile(
            key: const Key('signals'),
            title: Text(
              _report.signals.isEmpty ? '—' : _report.signals.join('\n'),
            ),
          ),
          const _Header('Policy preview'),
          _PolicyPreview(
            report: _report,
            choice: _choice,
            onChoice: (PolicyChoice choice) => setState(() => _choice = choice),
            onPreviewBlocked: _previewBlockedScreen,
          ),
          const _Header('Runtime monitor (every 15 s)'),
          ListTile(
            key: const Key('monitor'),
            title: Text('Checks so far: $_monitorTicks'),
            subtitle: Text(
              'Running: ${widget.monitor.isRunning}  ·  '
              'strikes: ${widget.monitor.strikes}\n'
              'Last violation: ${_lastViolation ?? 'none'}',
            ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        key: const Key('recheck'),
        onPressed: _checking ? null : _recheck,
        icon: const Icon(Icons.refresh),
        label: Text(_checking ? 'Checking…' : 'Check again'),
      ),
    );
  }

  static String _formatTime(DateTime time) {
    final DateTime local = time.toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return 'at ${two(local.hour)}:${two(local.minute)}:${two(local.second)}';
  }
}

class _PolicyPreview extends StatelessWidget {
  const _PolicyPreview({
    required this.report,
    required this.choice,
    required this.onChoice,
    required this.onPreviewBlocked,
  });

  final DeviceSecurityReport report;
  final PolicyChoice choice;
  final ValueChanged<PolicyChoice> onChoice;
  final ValueChanged<SentinelPolicy> onPreviewBlocked;

  @override
  Widget build(BuildContext context) {
    final SentinelPolicy policy = choice.policy;
    final SentinelResponse response = policy.responseTo(report);
    final String detail = switch (response) {
      SentinelResponse.block =>
        'BLOCK on ${describeThreats(policy.blocking(report))}',
      SentinelResponse.warn =>
        'WARN on ${describeThreats(policy.warning(report))}',
      SentinelResponse.ignore => 'IGNORE — nothing this policy cares about',
    };
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          SegmentedButton<PolicyChoice>(
            key: const Key('policy'),
            showSelectedIcon: false,
            segments: <ButtonSegment<PolicyChoice>>[
              for (final PolicyChoice c in PolicyChoice.values)
                ButtonSegment<PolicyChoice>(value: c, label: Text(c.label)),
            ],
            selected: <PolicyChoice>{choice},
            onSelectionChanged: (Set<PolicyChoice> selected) =>
                onChoice(selected.single),
          ),
          const SizedBox(height: 12),
          Text(
            detail,
            key: const Key('policy-result'),
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          OutlinedButton(
            key: const Key('preview-blocked'),
            onPressed: response == SentinelResponse.block
                ? () => onPreviewBlocked(policy)
                : null,
            child: const Text('Preview blocked screen'),
          ),
        ],
      ),
    );
  }
}

class _Header extends StatelessWidget {
  const _Header(this.title);

  final String title;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.fromLTRB(16, 20, 16, 4),
    child: Text(
      title,
      style: Theme.of(context).textTheme.labelLarge?.copyWith(
        color: Theme.of(context).colorScheme.primary,
      ),
    ),
  );
}
