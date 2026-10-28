/// A single signal a device check can raise.
///
/// Every value is a **client-side heuristic**. A determined attacker who
/// controls the device can hide any of them (see the README's "Threat model").
/// Treat a clean report as "no evidence found", never as proof of integrity.
enum DeviceThreat {
  /// Android emulator (build properties) or iOS Simulator (compile target).
  emulator,

  /// Android: `su` binaries, Magisk/SuperSU paths or root-manager apps.
  rooted,

  /// iOS: jailbreak files, package-manager URL schemes, a writable `/private`
  /// or suspicious symlinks.
  jailbroken,

  /// A debugger is attached right now (Android `Debug.isDebuggerConnected`,
  /// iOS `P_TRACED`).
  debuggerAttached,

  /// The app binary itself was built debuggable. Informational: every debug
  /// build has it, so the built-in policies never block on it.
  debuggableBuild,

  /// Frida server, gadget or agent: known files, loaded libraries or an open
  /// Frida port on the loopback interface.
  frida,

  /// A hooking framework: Xposed/LSPosed (Android), Cydia Substrate or a
  /// method swizzled from outside the system and the app bundle (iOS).
  hookingFramework,

  /// Reverse-engineering, traffic-capture, memory-editing or app-cloning tools
  /// installed or injected (Android packages, `libreveal`/`sslkillswitch`).
  reverseEngineeringTools,

  /// The app was re-signed or repackaged: signing certificate (Android) or
  /// bundle identifier, injected dylibs, missing code signature (iOS).
  ///
  /// Only checked in release builds, and only against the identities given in
  /// `SentinelConfig`.
  tampered,

  /// The native reply did not echo the request nonce. Either the reply was
  /// replaced in transit (a naive channel hook) or the native side is from a
  /// different plugin version. Not a cryptographic guarantee.
  channelMismatch,

  /// The check itself failed or timed out, so there is no evidence either way.
  /// The built-in policies never block on this: a stalled check must not lock
  /// legitimate users out.
  checkFailed,
}
