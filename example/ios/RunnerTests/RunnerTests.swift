import Flutter
import UIKit
import XCTest

@testable import device_sentinel_security

/// Unit tests for the plugin's native probe logic. The path rules take an
/// explicit `inSimulator:` so the device behaviour is tested here too.
class RunnerTests: XCTestCase {
  private let bundle = "/private/var/containers/Bundle/Application/ABC/Runner.app"

  func testFridaImageNamesMatchFridaButNotLookalikes() {
    for name in ["fridagadget.dylib", "frida-agent.dylib", "libfrida-gadget.dylib", "libgadget.dylib"] {
      XCTAssertTrue(InstrumentationChecks.isFridaImageName(name), name)
    }
    for name in ["fridaykit", "libfriday.dylib", "gadgetstore", "flutter"] {
      XCTAssertFalse(InstrumentationChecks.isFridaImageName(name), name)
    }
  }

  func testSystemImagesAreAPrefixOnADevice() {
    XCTAssertTrue(InstrumentationChecks.isSystemImage(
      "/System/Library/Frameworks/Foundation.framework/Foundation", inSimulator: false))
    // A repackaged bundle cannot hide a dylib in its own System/Library folder.
    XCTAssertFalse(InstrumentationChecks.isSystemImage(
      "\(bundle)/System/Library/FridaGadget.dylib", inSimulator: false))
    // The simulator runtime lives under a Mac path.
    XCTAssertTrue(InstrumentationChecks.isSystemImage(
      "/Library/Developer/CoreSimulator/Volumes/iOS/RuntimeRoot/System/Library/Frameworks/UIKit.framework/UIKit",
      inSimulator: true))
  }

  func testHookOriginsTrustTheOSToolsAndBundleOnly() {
    func trusted(_ image: String) -> Bool {
      InstrumentationChecks.isTrustedHookOrigin(image, bundlePath: bundle, inSimulator: false)
    }
    XCTAssertTrue(trusted("/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore"))
    XCTAssertTrue(trusted("/Developer/usr/lib/libMainThreadChecker.dylib"))
    XCTAssertTrue(trusted("\(bundle)/Frameworks/App.framework/App"))
    // Rootful jailbreaks load tweaks from here.
    XCTAssertFalse(trusted("/usr/lib/TweakInject/HideJailbreak.dylib"))
    XCTAssertFalse(trusted("\(bundle)x/evil.dylib"))
  }

  func testCheckDeviceEchoesTheNonceAndReportsTheSimulator() {
    let plugin = DeviceSentinelSecurityPlugin()
    let call = FlutterMethodCall(methodName: "checkDevice", arguments: ["nonce": "n-1"])

    let answered = expectation(description: "result block must be called.")
    plugin.handle(call) { result in
      let reply = result as? [String: Any]
      XCTAssertEqual(reply?["nonce"] as? String, "n-1")
      XCTAssertEqual(reply?["emulator"] as? Bool, true)
      // No false positives from the stock simulator runtime.
      XCTAssertEqual(reply?["frida"] as? Bool, false)
      XCTAssertEqual(reply?["hookingFramework"] as? Bool, false, "\(reply?["signals"] ?? "")")
      XCTAssertEqual(reply?["jailbroken"] as? Bool, false)
      answered.fulfill()
    }
    waitForExpectations(timeout: 5)
  }

  func testUnknownMethodsAreNotImplemented() {
    let plugin = DeviceSentinelSecurityPlugin()
    let call = FlutterMethodCall(methodName: "getPlatformVersion", arguments: nil)

    let answered = expectation(description: "result block must be called.")
    plugin.handle(call) { result in
      XCTAssertTrue((result as AnyObject) === FlutterMethodNotImplemented)
      answered.fulfill()
    }
    waitForExpectations(timeout: 1)
  }
}
