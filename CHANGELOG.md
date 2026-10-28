## 0.1.1

* Shorten the package description to fit pub.dev's 60–180 character limit.

## 0.1.0

* Initial release.
* `DeviceSentinel.checkDevice()` with typed `DeviceSecurityReport` and probe
  `signals`; `watch()` report stream.
* Android: emulator, root, debugger, Frida, Xposed, reverse-engineering tools
  and signing-certificate tamper checks, on a background task queue.
* iOS: simulator, jailbreak, debugger, Frida, Substrate, method-swizzle and
  bundle/code-signature tamper checks, on a background task queue.
* `SentinelPolicy` (strict / instrumentationOnly / reportOnly / off, or
  custom), `SentinelMonitor` with strike-based escalation, optional
  `SentinelGuard` UI.
* R8 `consumer-rules.pro` and `build_obfuscated` helper for build-time
  obfuscation.
