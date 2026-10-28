# device_sentinel_security

Client-side device security checks for Flutter apps on **Android** and **iOS**:

- **Emulator / simulator** detection
- **Root** detection (Android) and **jailbreak** detection (iOS)
- **Anti-reverse-engineering**: attached debugger, Frida, hooking frameworks
  (Xposed/LSPosed, Cydia Substrate, swizzled methods), reverse-engineering
  tools, and **tamper** (re-signed / repackaged app) checks
- A **runtime monitor** that re-checks on an interval
- A **host-defined policy** (block / warn / ignore per threat, per build type)
  and optional, fully replaceable UI
- **Obfuscation support** for release builds — which is a *build-time* step,
  see [Obfuscation](#obfuscation-is-build-time-not-runtime)

## Threat model — read this first

**Every check in this package runs on the device and can be defeated by
whoever controls that device.** A determined attacker can patch the native
code, hook the platform channel, hide root with Magisk DenyList / Shamiko, or
hide a jailbreak with a tweak. These checks raise the cost of casual
tampering and give you telemetry about the devices your app runs on. They
are **not** proof of device integrity.

For anything that must be trusted — login, payments, rewards — verify the
device **server-side** with
[Play Integrity](https://developer.android.com/google/play/integrity) (Android)
and [App Attest](https://developer.apple.com/documentation/devicecheck)
(iOS). Treat a clean report as "no evidence found", never as "safe".

The request/reply nonce described below catches a stale native build or a
naive channel replacement. It is a consistency check, not a cryptographic
guarantee: its value lives in the same process an attacker controls.

## What is checked

| `DeviceThreat` | Android | iOS |
|---|---|---|
| `emulator` | `Build` fingerprint, model, manufacturer, brand/device, product, hardware (`goldfish`, `ranchu`), Nox markers | `targetEnvironment(simulator)` |
| `rooted` | `su` / Magisk / SuperSU paths, root-manager packages, `su` on `PATH` | — |
| `jailbroken` | — | Jailbreak files (incl. rootless `/var/jb`), package-manager URL schemes*, write outside the sandbox, suspicious symlinks. Skipped on the simulator. |
| `debuggerAttached` | `Debug.isDebuggerConnected()` / `waitingForDebugger()` | `sysctl` `P_TRACED` |
| `debuggableBuild` | `FLAG_DEBUGGABLE` (informational) | `#if DEBUG` (informational) |
| `frida` | frida-server files, Frida libraries in `/proc/self/maps`, Frida threads (`gum-js-loop`, `pool-frida`), Frida ports in `/proc/net/tcp` (Android 9 and older), loopback connect to 27042/27043 | Frida images loaded by dyld, loopback connect to 27042/27043 |
| `hookingFramework` | Xposed frames on the main or current thread's stack, `XposedBridge` on the boot class path, Xposed files | Substrate files and images, `FileManager.fileExists` / `UIApplication.canOpenURL` implemented outside the system, Xcode tools and the app bundle |
| `reverseEngineeringTools` | Hooking, traffic-capture, patcher and app-cloner packages; `libreveal` / `sslkillswitch` in memory | — |
| `tampered` | No signing certificate in your allow-list (release builds only) | Bundle ID not in your list, injected inspection dylibs, no `LC_CODE_SIGNATURE` (release builds only) |
| `channelMismatch` | Reply did not echo the request nonce | same |
| `checkFailed` | The check threw, timed out or the plugin is missing | same |

\* only for schemes your app lists under `LSApplicationQueriesSchemes`.

Each report also carries `signals`: short fixed ids such as `root.path`,
`frida.port` or `tamper.signature` saying which probe fired. They contain no
paths, package names or user data, so they are safe to send to analytics and
are the first thing to look at when a legitimate device is flagged.
`tamper.unverifiable` means the signing certificates could not be read on
that check (it is retried on the next one), and `config.invalid_fingerprint`
means your own `SentinelConfig` is wrong (see below).

## Install

```yaml
dependencies:
  device_sentinel_security: ^0.1.0
```

Requires Flutter 3.44+. Android `minSdk` 24. iOS 13+ (Xcode 27 itself
requires a 15.0 deployment target — see the example's `Podfile`).

### Android

Nothing to add. The plugin's manifest declares `<queries>` for the specific
root-manager and tool packages it looks for; without them Android 11+ hides
those apps and the package checks always report "not installed". No
`QUERY_ALL_PACKAGES` is needed. To drop an entry, remove it in your own
manifest with `tools:node="remove"`.

The loopback Frida probe needs `android.permission.INTERNET`, which almost
every app already has; without it that probe silently reports false.

### iOS

Optional: to enable the package-manager URL-scheme check, add the schemes to
your `Info.plist`. Schemes you do not list are skipped (querying an unlisted
scheme only logs an error and always answers false).

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
  <string>cydia</string>
  <string>sileo</string>
  <string>zbra</string>
</array>
```

App Review may ask why you query these schemes; leave them out if that is a
concern — the file-based checks still run.

## Usage

### 1. Configure the identities your release build carries

```dart
const config = SentinelConfig(
  // Upload key AND Play App Signing key: SHA-256, as printed by keytool,
  // apksigner or the Play Console (labels and colons optional).
  androidSigningCertSha256: [
    'AB:CD:…',
    'EF:01:…',
  ],
  // One per flavor / scheme.
  iosBundleIds: ['com.example.app', 'com.example.app.staging'],
);
final sentinel = DeviceSentinel(config: config);
```

Leave a list empty to skip that part of the tamper check. Tamper is never
checked in debug builds, so debug keys never trip it.

An Android entry that is not a SHA-256 fingerprint — most often the SHA-1
the Play Console shows right next to it — fails an assertion when
`DeviceSentinel` is created in a debug build. In release the Android
signature comparison is skipped instead, and every report carries the
`config.invalid_fingerprint` signal: a wrong allow-list must not brand every
genuine install as tampered.

### 2. Pick a policy — the host decides, not the plugin

```dart
final policy = SentinelPolicy.forBuildMode(
  release: isProductionFlavor
      ? SentinelPolicy.strict
      : SentinelPolicy.instrumentationOnly,
  // debug and profile default to SentinelPolicy.reportOnly
);
```

| Policy | Blocks on | Warns on |
|---|---|---|
| `strict` | emulator, rooted, jailbroken, debugger, Frida, hooking, RE tools, tampered, channel mismatch | check failed |
| `instrumentationOnly` | Frida, hooking, channel mismatch | everything else except `debuggableBuild` |
| `reportOnly` | nothing | everything except `debuggableBuild` and `debuggerAttached` |
| `off` | nothing | nothing |

Or build your own: `SentinelPolicy(block: {...}, warn: {...})`. No built-in
policy blocks on `checkFailed`: a stalled or crashed check must never lock
legitimate users out.

### 3. Check at boot

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final report = await sentinel.checkDevice(); // never throws

  if (policy.responseTo(report) == SentinelResponse.block) {
    runApp(MyBlockedApp(threats: policy.blocking(report)));
    return;
  }
  runApp(MyApp(bootReport: report));
}
```

`checkDevice()` times out after 10 seconds by default
(`DeviceSentinel(timeout: …)`) and reports `checkFailed` instead of hanging.

### 4. Monitor at runtime

```dart
final monitor = SentinelMonitor(
  sentinel: sentinel,
  policy: policy,
  interval: const Duration(seconds: 30),
  strikesToBlock: 3, // non-instrumentation threats must repeat to block
);
monitor.violations.listen((v) => analytics.log('sentinel', v.report.toTelemetry()));
monitor.start();
```

Frida, hooking, an attached debugger and a channel mismatch block on first
sight (`SentinelMonitor.defaultBlockImmediately`). Any other blocking threat
is reported as `warn` until it has been seen in `strikesToBlock` consecutive
checks, so one flaky probe cannot lock a user out. A check without a
blocking threat resets the count; a failed check (`checkFailed`) leaves it
as is, so a check that keeps timing out cannot hold a real threat below the
limit. The monitor stops itself after a block (`stopOnBlock`) and remembers
it in `monitor.blockedBy`.

If a check times out but is still running natively, later ticks report
`checkFailed` (`stalled`) instead of queueing more native work behind it.

`sentinel.watch(interval: …)` gives you the raw report stream instead.

### 5. Optional UI

```dart
MaterialApp(
  builder: (context, child) => SentinelGuard(
    monitor: monitor,
    initialReport: bootReport,
    blockedBuilder: (context, violation) => MyBlockedScreen(violation),
    warningBuilder: (context, violation, dismiss) => MyBanner(onClose: dismiss),
    child: child!,
  ),
)
```

`SentinelGuard` shows the child until a violation arrives, then swaps in a
blocked view or shows a warning banner above the app. A warning goes away
when the user dismisses it or a later check no longer raises it. A block is
final: a guard that is rebuilt or remounted reads `monitor.blockedBy` and
stays blocked. The defaults
(`SentinelBlockedView`, `SentinelWarningBanner`) are plain Material widgets
with English text — pass your own builders to localise or brand them. The
default blocked view has **no** close button unless you pass `onClose`; how
(and whether) the app exits is your decision. Note that iOS ignores
`SystemNavigator.pop`, so offer an exit button on Android only.

### Testing your app

Inject a fake transport instead of touching the platform channel:

```dart
class FakePlatform extends Fake
    with MockPlatformInterfaceMixin
    implements DeviceSentinelPlatform { … }

final sentinel = DeviceSentinel(platform: FakePlatform(), nonceFactory: () => 'n');
```

## Threading

Both native handlers are registered on a **background task queue**
(`makeBackgroundTaskQueue`). The checks stat dozens of paths, read `/proc`,
query the package manager and open loopback sockets; running that on the
platform thread on every monitor tick would cause ANRs and jank. The one UIKit
call (`canOpenURL`) hops to the main thread on its own. No check forks a
process (`ps`, `which su`): with `hidepid` on `/proc` a `ps` scan cannot see
root-owned processes anyway, and a fork on every tick is expensive.

## Obfuscation is build-time, not runtime

**A runtime plugin cannot obfuscate your app.** Obfuscation happens when you
build the release, so this package ships the pieces for that step instead:

**Dart** — build releases with both flags, and keep the symbols:

```bash
flutter build appbundle --release --obfuscate --split-debug-info=build/symbols/android
flutter build ipa --release --obfuscate --split-debug-info=build/symbols/ios
```

or let the bundled helper add them:

```bash
dart run device_sentinel_security:build_obfuscated appbundle ipa \
  --flavor prod -t lib/main_prod.dart --symbols build/symbols
```

Archive the symbols directory with each release and upload it to your crash
reporter — obfuscated stack traces are unreadable without it.

**Android (R8)** — the plugin ships `consumer-rules.pro`, merged into your
release build automatically. It keeps only the plugin entry point (Flutter
instantiates it by name) and lets R8 rename, inline and repackage the check
classes, so a decompiler shows `d0.b` instead of `EnvironmentChecks`. Make
sure your app's release build type has `isMinifyEnabled = true`. Don't add
broad `-keep` rules for this package: they give a reverse engineer readable
names to hook.

**iOS** — Flutter's `--obfuscate` covers Dart only. Swift is compiled to
native code with symbols stripped in release, but there is no obfuscation
step for it.

## Known limitations

- All checks are client-side and forgeable (see the threat model).
- Root hiding (Magisk DenyList, Zygisk modules, KernelSU) and rootless
  jailbreak hiding tweaks defeat file- and package-based checks.
- `/proc/net/tcp` is not readable by apps on Android 10+ (SELinux), so it is
  only read on Android 9 and older; the loopback
  connect probe covers Frida's default ports, but not a relocated
  frida-server.
- The iOS hook check inspects two methods; hooks elsewhere go unseen.
- The `LC_CODE_SIGNATURE` check is weak: stock iOS will not launch an
  unsigned binary anyway.
- Emulator heuristics are property-based; a custom emulator image can spoof
  them.

## License

MIT — see [LICENSE](LICENSE).
