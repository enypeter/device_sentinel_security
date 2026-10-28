# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Flutter **plugin** package (`device_sentinel_security`, Android + iOS) that runs client-side device checks: emulator, root/jailbreak, debugger, Frida, hooking, reverse-engineering tools, and tamper. The checks run natively. Dart owns the transport, the report model, the policy, the runtime monitor and the optional UI. `README.md` is the user-facing spec: its threat table, policy table and behaviour notes must stay accurate when behaviour changes.

## Commands

```bash
flutter pub get
flutter analyze                                   # lints: package:flutter_lints/flutter.yaml
dart format .
flutter test                                      # Dart unit/widget tests in test/
flutter test test/sentinel_monitor_test.dart      # one file
flutter test --plain-name "<test name>"           # one test

# Real native checks; expects a debug build on an emulator/simulator
# (it asserts emulator == true and debuggableBuild == true).
cd example && flutter test integration_test -d <device>

# Kotlin JVM unit tests (android/src/test). The example must have been
# configured once, e.g. `cd example && flutter build apk --config-only`.
cd example/android && ./gradlew :device_sentinel_security:testDebugUnitTest

# Swift unit tests live in example/ios/RunnerTests (XCTest, `@testable import device_sentinel_security`);
# run them from Xcode in example/ios/Runner.xcworkspace or via xcodebuild test on a simulator.

pod lib lint ios/device_sentinel_security.podspec  # before publishing
```

`bin/build_obfuscated.dart` is a CLI that host apps run (`dart run device_sentinel_security:build_obfuscated …`) to wrap `flutter build` with `--obfuscate --split-debug-info`. It is not part of this repo's own build.

## Architecture

### The channel contract (Dart ⇄ native)

There is exactly one method, `checkDevice`, on the `MethodChannel` named `device_sentinel_security`:

- **Request args:** `nonce` (random hex per call), `androidSigningCertSha256` (already normalised to lower-case hex by `SentinelConfig.toChannelArguments()`, or emptied if any entry is invalid), and `iosBundleIds`.
- **Reply:** echoes `nonce`, has one `bool` per `DeviceThreat.name`, and a `signals` list of strings. Each platform returns **every** native threat key and hard-codes the ones it does not apply to as `false` (Android `jailbroken`; iOS `rooted`, `reverseEngineeringTools`).
- `DeviceSecurityReport.fromChannelReply` ignores unknown keys and treats missing keys as false, so Dart and native can drift without crashing.
- `channelMismatch` and `checkFailed` are **Dart-only** threats and native never sends them. `DeviceSentinel.checkDevice()` adds `channelMismatch` when the nonce is not echoed, and turns any timeout or exception into `DeviceSecurityReport.failed(reason)`. `checkDevice()` never throws.

**Adding or renaming a threat** touches: the `DeviceThreat` enum, both native `checkDevice` maps (`DeviceSentinelSecurityPlugin.kt` / `.swift`), the built-in policies in `sentinel_policy.dart`, the README tables, and `nativeReply()` in `test/helpers.dart`.

### Native side layout (mirrored on both platforms)

`android/src/main/kotlin/.../` and `ios/device_sentinel_security/Sources/device_sentinel_security/` each contain:
- `DeviceSentinelSecurityPlugin`: registers the channel on a **serial background task queue** (`makeBackgroundTaskQueue`) and assembles the reply map.
- `EnvironmentChecks`: emulator, root/jailbreak, debugger, debuggable build.
- `InstrumentationChecks`: Frida, hooking frameworks, RE tools.
- `TamperCheck`: signing cert (Android) or bundle id / injected dylibs / `LC_CODE_SIGNATURE` (iOS).
- `Signals`: collects fired probe ids. Probes use the idiom `return signals.hit("area.probe")`.

The iOS sources are shared by CocoaPods (`ios/device_sentinel_security.podspec`) and SwiftPM (`ios/device_sentinel_security/Package.swift`).

Pure matching logic is pulled out of the platform calls so it can be unit-tested without a device. Examples: `InstrumentationChecks.isFridaLibraryName`, `TamperCheck.check(allowed, signals) { readCertificates }`, and the iOS helpers that take an explicit `inSimulator:` argument. Follow that pattern when adding probes.

### Dart layers (`lib/src/`)

`DeviceSentinel` (one check, plus `watch()` stream) → `SentinelPolicy` (host-chosen block/warn sets) → `SentinelMonitor` (periodic checks plus strike escalation) → `SentinelGuard` widget (optional UI, reads `monitor.blockedBy` so a remount stays blocked).

- `DeviceSentinel` counts timed-out native calls that are still running (`_stalledNativeCalls`). The native queue is serial, so while that count is non-zero, `watch()` emits `failed('stalled')` instead of queueing more work. A tick that arrives during an in-flight check is skipped, not queued.
- `SentinelMonitor.evaluate`: threats in `blockImmediately` (Frida, hooking, debugger, channel mismatch) block on first sight. Other blocking threats `warn` until they appear in `strikesToBlock` consecutive checks. A clean check resets the strike count, but a `checkFailed` check leaves it unchanged.
- Everything injectable for tests: `DeviceSentinel(platform:, nonceFactory:, clock:)`, `SentinelPolicy.selectForBuildMode(isRelease:, isProfile:, …)`. Tests use `mocktail` mocks from `test/helpers.dart` and `fake_async` for timer-driven behaviour.

## Invariants to preserve

- **No built-in policy blocks on `checkFailed` or `debuggableBuild`.** A stalled check or a debug build must never lock users out.
- **Signals are fixed short ids** (`root.path`, `frida.port`, `tamper.signature`, …). Never put paths, package names or user data in them, because they are documented as safe for analytics.
- **Native handlers must never crash the host.** On Android, `onMethodCall` catches `Throwable` (not just `Exception`), because an `Error` thrown from a task queue kills the app.
- **Tamper is skipped in debug builds**, decided at build time (`BuildConfig.DEBUG` on Android, `#if DEBUG` on iOS). Never use the runtime debuggable flag for this, because a repackager can flip it. Android caches the tamper result only after a successful certificate read; an unreadable signature reports `tamper.unverifiable` and is retried on the next check.
- **A malformed Android fingerprint (e.g. SHA-1) disables the signature comparison** rather than flagging every install. Debug builds get an assert, and release reports get the `config.invalid_fingerprint` signal.
- **No process forking** (`ps`, `which su`) and no `QUERY_ALL_PACKAGES`. Package lookups depend on `<queries>` in `android/src/main/AndroidManifest.xml`, which must stay in sync with `EnvironmentChecks.rootManagerPackages` and `InstrumentationChecks.toolPackages`.
- **`android/consumer-rules.pro` keeps only the plugin class's constructor.** Do not add broad `-keep` rules, because readable check names make the checks easy to hook.
- The nonce is a consistency check, not a security guarantee. Keep docs and comments honest about the client-side threat model (see README "Threat model").
