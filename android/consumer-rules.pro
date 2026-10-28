# device_sentinel_security — R8 rules merged into the host app's release build.
#
# Only the plugin entry point needs a stable name: Flutter's generated
# GeneratedPluginRegistrant instantiates it by class name. Everything else
# (the check objects, probe lists, signal ids' call sites) is referenced
# directly from Kotlin, so R8 may rename, inline and repackage it — which is
# exactly what makes the checks harder to find and hook in a decompiler.
#
# Do NOT add broad keeps here such as `-keep class dev.devicesentinel.** { *; }`:
# they leave readable names like `isRooted` for a jadx reader or a Frida script.
-keep class dev.devicesentinel.device_sentinel_security.DeviceSentinelSecurityPlugin {
    public <init>();
}
