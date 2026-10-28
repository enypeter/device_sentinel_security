// Builds a release with Dart obfuscation and split debug info.
//
// Obfuscation is a BUILD-TIME step: nothing this package does at runtime can
// obfuscate your Dart code. This script only wraps the two flags Flutter needs
// so they are never forgotten on a release build.
//
// Run from the host app's root:
//
//   dart run device_sentinel_security:build_obfuscated appbundle ipa \
//     --flavor prod -t lib/main_prod.dart --symbols build/symbols
//
// Anything after `--` is passed to `flutter build` unchanged.
import 'dart:io';

const List<String> _targets = <String>['apk', 'appbundle', 'ipa', 'ios'];

const String _usage = '''
Usage: dart run device_sentinel_security:build_obfuscated <target>... [options] [-- <flutter build args>]

Targets: apk, appbundle, ipa, ios

Options:
  -t, --target <file>   Entry point (default: lib/main.dart)
  --flavor <name>       Build flavor / iOS scheme
  --symbols <dir>       Where to write split debug info (default: build/symbols)
  -h, --help            Show this help

Keep the symbols directory: without it, obfuscated stack traces cannot be
read. Upload it to your crash reporter (e.g. `firebase crashlytics:symbols:upload`).''';

Future<void> main(List<String> arguments) async {
  final List<String> targets = <String>[];
  final List<String> passthrough = <String>[];
  String entry = 'lib/main.dart';
  String symbols = 'build/symbols';
  String? flavor;

  for (int i = 0; i < arguments.length; i++) {
    final String arg = arguments[i];
    String value() {
      if (i + 1 >= arguments.length) _fail('Missing value for $arg');
      return arguments[++i];
    }

    switch (arg) {
      case '--':
        passthrough.addAll(arguments.skip(i + 1));
        i = arguments.length;
      case '-h' || '--help':
        stdout.writeln(_usage);
        return;
      case '-t' || '--target':
        entry = value();
      case '--flavor':
        flavor = value();
      case '--symbols':
        symbols = value();
      default:
        if (!_targets.contains(arg)) _fail('Unknown argument: $arg');
        targets.add(arg);
    }
  }

  if (targets.isEmpty) _fail('Pass at least one target.');

  for (final String target in targets) {
    final List<String> command = <String>[
      'build',
      target,
      '--release',
      '--obfuscate',
      '--split-debug-info=$symbols/$target',
      '-t',
      entry,
      if (flavor != null) ...<String>['--flavor', flavor],
      ...passthrough,
    ];
    stdout.writeln('> flutter ${command.join(' ')}');
    final Process process = await Process.start(
      'flutter',
      command,
      mode: ProcessStartMode.inheritStdio,
      runInShell: Platform.isWindows,
    );
    final int code = await process.exitCode;
    if (code != 0) exit(code);
  }

  stdout.writeln('Done. Archive "$symbols" with this build for symbolication.');
}

Never _fail(String message) {
  stderr
    ..writeln(message)
    ..writeln()
    ..writeln(_usage);
  exit(64);
}
