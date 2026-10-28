#
# Run `pod lib lint device_sentinel_security.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'device_sentinel_security'
  s.version          = '0.1.0'
  s.summary          = 'Client-side jailbreak, simulator, debugger, Frida, hooking and tamper checks for Flutter.'
  s.description      = <<-DESC
Native iOS side of the device_sentinel_security Flutter plugin: jailbreak,
simulator, debugger, Frida, Cydia Substrate, method-swizzle and tamper checks,
run off the main thread.
                       DESC
  s.homepage         = 'https://pub.dev/packages/device_sentinel_security'
  s.license          = { :file => '../LICENSE' }
  s.author           = 'enypieter'
  s.source           = { :path => '.' }
  s.source_files = 'device_sentinel_security/Sources/device_sentinel_security/**/*.swift'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # No required-reason APIs and no data collection; shipped so App Store
  # privacy reports list the plugin explicitly.
  s.resource_bundles = {'device_sentinel_security_privacy' => ['device_sentinel_security/Sources/device_sentinel_security/PrivacyInfo.xcprivacy']}
end
