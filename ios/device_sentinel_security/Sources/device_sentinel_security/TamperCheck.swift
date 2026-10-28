import Foundation
import MachO

/// Detects a repackaged or modified app. Release builds only.
enum TamperCheck {
    /// Libraries injected to inspect or patch an app; their presence in our
    /// process means the IPA was modified or the process was injected into.
    private static let injectedLibraryPrefixes = [
        "libcycript", "libsubstrate", "libreveal", "libssl_hook", "sslkillswitch", "snoop",
    ]
    /// FLEX is matched exactly: "flex" as a prefix would flag legitimate
    /// libraries such as FlexLayout.
    private static let injectedLibraryStems: Set<String> = ["flex", "libflex", "flexing", "libflexing"]

    static func isTampered(expectedBundleIds: [String], images: [String], _ signals: Signals) -> Bool {
        #if DEBUG
        return false
        #else
        if !expectedBundleIds.isEmpty {
            guard let bundleId = Bundle.main.bundleIdentifier, expectedBundleIds.contains(bundleId) else {
                return signals.hit("tamper.bundle_id")
            }
            // Re-read the identifier from the raw Info.plist in case the
            // runtime accessor was hooked.
            if let path = Bundle.main.path(forResource: "Info", ofType: "plist"),
               let plist = NSDictionary(contentsOfFile: path),
               let plistId = plist["CFBundleIdentifier"] as? String,
               !expectedBundleIds.contains(plistId) {
                return signals.hit("tamper.info_plist")
            }
        }
        // Embedded provisioning profiles are not checked: installed bundles
        // from TestFlight and other channels do not carry one, so it produces
        // false positives.
        let isInjected = { (image: String) in
            injectedLibraryPrefixes.contains(where: { image.hasPrefix($0) })
                || injectedLibraryStems.contains(InstrumentationChecks.stem(of: image))
        }
        if images.contains(where: isInjected) { return signals.hit("tamper.injected_library") }
        if !mainExecutableHasCodeSignature() { return signals.hit("tamper.no_code_signature") }
        return false
        #endif
    }

    /// Walks the main executable's in-memory load commands for
    /// LC_CODE_SIGNATURE. Weak on its own — stock iOS refuses to launch an
    /// unsigned binary — but it catches a stripped signature on jailbroken
    /// devices, where that check is disabled.
    static func mainExecutableHasCodeSignature() -> Bool {
        guard let header = _dyld_get_image_header(0) else { return false }
        let base = UnsafeRawPointer(header)
        let headerSize: Int
        switch header.pointee.magic {
        case MH_MAGIC_64: headerSize = MemoryLayout<mach_header_64>.size
        case MH_MAGIC: headerSize = MemoryLayout<mach_header>.size
        default: return false
        }
        var cursor = base + headerSize
        for _ in 0..<header.pointee.ncmds {
            let command = cursor.assumingMemoryBound(to: load_command.self).pointee
            if command.cmd == UInt32(LC_CODE_SIGNATURE) { return true }
            guard command.cmdsize > 0 else { return false }
            cursor += Int(command.cmdsize)
        }
        return false
    }
}
