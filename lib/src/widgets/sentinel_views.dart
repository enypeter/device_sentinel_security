import 'package:flutter/material.dart';

import '../device_threat.dart';
import '../sentinel_monitor.dart';

/// Readable names for threats, for the default views. Hosts that localise
/// should pass their own text instead.
String describeThreats(Iterable<DeviceThreat> threats) =>
    threats.map((DeviceThreat threat) => threat.name).join(', ');

/// A minimal full-screen "cannot continue" view. Every string is overridable,
/// and there is no close button unless [onClose] is given — the host decides
/// how (and whether) the app exits.
class SentinelBlockedView extends StatelessWidget {
  const SentinelBlockedView({
    super.key,
    required this.violation,
    this.title = 'Security check failed',
    this.message = 'This app cannot run on this device.',
    this.showThreats = true,
    this.onClose,
    this.closeLabel = 'Close',
  });

  final SentinelViolation violation;
  final String title;
  final String message;

  /// Appends the raised threat names below [message].
  final bool showThreats;

  /// Called by the close button; the button is hidden when null.
  final VoidCallback? onClose;
  final String closeLabel;

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return PopScope(
      canPop: false,
      child: Material(
        color: theme.colorScheme.surface,
        child: SafeArea(
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(32),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: <Widget>[
                  Icon(
                    Icons.shield_outlined,
                    size: 72,
                    color: theme.colorScheme.error,
                  ),
                  const SizedBox(height: 24),
                  Text(
                    title,
                    textAlign: TextAlign.center,
                    style: theme.textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    message,
                    textAlign: TextAlign.center,
                    style: theme.textTheme.bodyLarge,
                  ),
                  if (showThreats) ...<Widget>[
                    const SizedBox(height: 8),
                    Text(
                      '(${describeThreats(violation.threats)})',
                      textAlign: TextAlign.center,
                      style: theme.textTheme.bodySmall,
                    ),
                  ],
                  if (onClose != null) ...<Widget>[
                    const SizedBox(height: 32),
                    FilledButton(onPressed: onClose, child: Text(closeLabel)),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A dismissible strip for [SentinelResponse.warn] violations.
class SentinelWarningBanner extends StatelessWidget {
  const SentinelWarningBanner({
    super.key,
    required this.violation,
    required this.onDismiss,
    this.label = 'Security warning',
  });

  final SentinelViolation violation;
  final VoidCallback onDismiss;
  final String label;

  @override
  Widget build(BuildContext context) {
    final ColorScheme colors = Theme.of(context).colorScheme;
    return Material(
      color: colors.tertiaryContainer,
      elevation: 2,
      child: Padding(
        padding: const EdgeInsetsDirectional.only(start: 16, end: 4),
        child: Row(
          children: <Widget>[
            Icon(
              Icons.warning_amber_rounded,
              color: colors.onTertiaryContainer,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                '$label: ${describeThreats(violation.threats)}',
                style: TextStyle(color: colors.onTertiaryContainer),
              ),
            ),
            // No tooltip: SentinelGuard usually sits in MaterialApp.builder,
            // above the Navigator, where there is no Overlay to show one in.
            Semantics(
              button: true,
              label: MaterialLocalizations.of(context).closeButtonTooltip,
              excludeSemantics: true,
              child: IconButton(
                icon: Icon(Icons.close, color: colors.onTertiaryContainer),
                onPressed: onDismiss,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
