import Foundation
import MachO
import ObjectiveC
import UIKit

/// Frida, Cydia Substrate and method-hook checks.
enum InstrumentationChecks {
    /// Frida's own image names, matched as tokens: the bare word "frida"
    /// would also match a framework called FridayKit.
    private static let fridaImageNeedles = ["frida-agent", "frida-gadget", "fridagadget"]
    /// "gadget" alone is too common to match as a substring.
    private static let fridaImageStems: Set<String> = ["gadget", "libgadget"]
    private static let substrateImageNeedles = ["substrate", "cycript"]
    private static let substratePaths = [
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/",
    ]
    private static let fridaPorts: [UInt16] = [27042, 27043]

    #if targetEnvironment(simulator)
    static let runsInSimulator = true
    #else
    static let runsInSimulator = false
    #endif

    /// Lower-cased FILE NAMES of the non-system images loaded into this
    /// process. Matching on the name, not the full path, matters: a full path
    /// includes the app's own bundle name, so a needle like "flex" would flag
    /// every user of an app called "FlexFit". System images are skipped
    /// because iOS ships frameworks such as FlexMusicKit.
    static func loadedImageNames() -> [String] {
        (0..<_dyld_image_count()).compactMap { index in
            guard let raw = _dyld_get_image_name(index) else { return nil }
            let path = String(cString: raw)
            if isSystemImage(path) { return nil }
            return (path as NSString).lastPathComponent.lowercased()
        }
    }

    /// An OS image. On a device this is a PREFIX test: a substring test would
    /// let a repackaged bundle hide a dylib in its own `…/System/Library/`
    /// folder and skip every image check. The simulator runtime lives under a
    /// Mac path, so there only a substring works; that is not security-
    /// relevant, because the simulator already reports `emulator`.
    static func isSystemImage(_ path: String, inSimulator: Bool = runsInSimulator) -> Bool {
        inSimulator ? path.contains("/System/Library/") : path.hasPrefix("/System/Library/")
    }

    /// Xcode's debugging libraries (the Main Thread Checker wraps UIKit
    /// methods), mounted from the Developer Disk Image on a device.
    static func isDeveloperToolImage(_ path: String, inSimulator: Bool = runsInSimulator) -> Bool {
        inSimulator
            ? path.contains("/Developer/")
            : path.hasPrefix("/Developer/") || path.hasPrefix("/System/Developer/")
    }

    /// Whether a method implementation found in `image` is expected: the OS,
    /// Xcode's debugging tools or this app's own bundle. `/usr/lib/` is NOT
    /// trusted: no guarded method is implemented there, and rootful jailbreaks
    /// load tweaks from `/usr/lib/TweakInject/`.
    static func isTrustedHookOrigin(
        _ image: String,
        bundlePath: String,
        inSimulator: Bool = runsInSimulator
    ) -> Bool {
        isSystemImage(image, inSimulator: inSimulator)
            || isDeveloperToolImage(image, inSimulator: inSimulator)
            || image.hasPrefix(bundlePath + "/")
    }

    /// `image` is a lower-cased file name from `loadedImageNames()`.
    static func isFridaImageName(_ image: String) -> Bool {
        fridaImageNeedles.contains(where: { image.contains($0) })
            || fridaImageStems.contains(stem(of: image))
    }

    static func hasFrida(images: [String], _ signals: Signals) -> Bool {
        if images.contains(where: isFridaImageName) { return signals.hit("frida.image") }
        if fridaPorts.contains(where: isLoopbackPortOpen) { return signals.hit("frida.port") }
        return false
    }

    static func hasHookingFramework(images: [String], _ signals: Signals) -> Bool {
        let fm = FileManager.default
        if substratePaths.contains(where: { fm.fileExists(atPath: $0) }) {
            return signals.hit("hook.substrate_path")
        }
        if images.contains(where: { image in substrateImageNeedles.contains(where: { image.contains($0) }) }) {
            return signals.hit("hook.substrate_image")
        }
        if hasForeignMethodHooks() { return signals.hit("hook.swizzle") }
        return false
    }

    /// The file name without its extension: `libgadget.dylib` → `libgadget`.
    static func stem(of image: String) -> String {
        (image as NSString).deletingPathExtension
    }

    /// A closed loopback port refuses at once, so this does not stall.
    private static func isLoopbackPortOpen(_ port: UInt16) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    /// Methods the jailbreak checks rely on. A tweak that hides a jailbreak
    /// swizzles exactly these.
    private static let guardedMethods: [(cls: AnyClass, selector: Selector)] = [
        (FileManager.self, #selector(FileManager.fileExists(atPath:))),
        (UIApplication.self, #selector(UIApplication.canOpenURL(_:))),
    ]

    /// True when a guarded method's implementation lives outside the system
    /// libraries, Apple's developer tools and this app's own bundle — i.e. in
    /// an injected tweak — or in no loaded image at all (a JIT trampoline).
    private static func hasForeignMethodHooks() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        for target in guardedMethods {
            guard let method = class_getInstanceMethod(target.cls, target.selector) else { continue }
            let imp = method_getImplementation(method)
            var info = Dl_info()
            guard dladdr(unsafeBitCast(imp, to: UnsafeRawPointer.self), &info) != 0,
                  let fname = info.dli_fname else {
                return true
            }
            if !isTrustedHookOrigin(String(cString: fname), bundlePath: bundlePath) { return true }
        }
        return false
    }
}
