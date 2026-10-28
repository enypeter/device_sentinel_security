import Foundation
import UIKit

/// Simulator, jailbreak, debugger and debug-build checks.
enum EnvironmentChecks {
    private static let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Applications/Sileo.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/etc/apt",
        "/etc/apt/sources.list.d/electra.list",
        "/etc/apt/sources.list.d/sileo.sources",
        "/private/var/lib/apt/",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/tmp/cydia.log",
        "/private/var/stash",
        "/private/var/Users/",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/bin/sshd",
        "/usr/bin/cycript",
        "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib",
        "/usr/lib/libjailbreak.dylib",
        "/usr/libexec/cydia/",
        "/usr/share/jailbreak/injectme.plist",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/var/lib/apt",
        "/var/jb",
        "/.bootstrapped_electra",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/.installed_dopamine",
        "/jb/lzma",
        "/jb/offsets.plist",
        "/jb/jailbreakd.plist",
        "/jb/amfid_payload.dylib",
        "/jb/libjailbreak.dylib",
    ]

    private static let suspiciousSymlinks = [
        "/var/stash",
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/arm-apple-darwin9",
    ]

    /// Package-manager schemes. `canOpenURL` answers only for schemes the
    /// HOST app lists under LSApplicationQueriesSchemes; any other scheme is
    /// skipped, rather than logging a refusal on every check.
    private static let jailbreakSchemes = ["cydia", "sileo", "zbra"]

    static func isSimulator(_ signals: Signals) -> Bool {
        #if targetEnvironment(simulator)
        return signals.hit("emulator.simulator")
        #else
        return false
        #endif
    }

    static func isDebuggableBuild(_ signals: Signals) -> Bool {
        #if DEBUG
        return signals.hit("build.debug")
        #else
        return false
        #endif
    }

    static func isDebuggerAttached(_ signals: Signals) -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else { return false }
        if (info.kp_proc.p_flag & P_TRACED) != 0 { return signals.hit("debugger.ptrace") }
        return false
    }

    static func isJailbroken(_ signals: Signals) -> Bool {
        #if targetEnvironment(simulator)
        // The simulator shares the Mac's filesystem; several paths above exist
        // on any Mac with Homebrew or Xcode tools. Reported as `emulator`.
        return false
        #else
        let fm = FileManager.default
        if jailbreakPaths.contains(where: { fm.fileExists(atPath: $0) }) {
            return signals.hit("jailbreak.path")
        }
        if canOpenJailbreakScheme() { return signals.hit("jailbreak.url_scheme") }
        if canWriteOutsideSandbox() { return signals.hit("jailbreak.sandbox_write") }
        for path in suspiciousSymlinks where (try? fm.destinationOfSymbolicLink(atPath: path)) != nil {
            return signals.hit("jailbreak.symlink")
        }
        return false
        #endif
    }

    private static func canOpenJailbreakScheme() -> Bool {
        let declared = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] ?? []
        let urls = jailbreakSchemes
            .filter { declared.contains($0) }
            .compactMap { URL(string: "\($0)://") }
        guard !urls.isEmpty else { return false }
        // UIKit must be touched on the main thread; this runs on the
        // channel's background queue, and the main thread is never blocked
        // waiting for it, so a synchronous hop cannot deadlock.
        let query = { urls.contains(where: { UIApplication.shared.canOpenURL($0) }) }
        return Thread.isMainThread ? query() : DispatchQueue.main.sync(execute: query)
    }

    private static func canWriteOutsideSandbox() -> Bool {
        let path = "/private/sentinel_\(UUID().uuidString).txt"
        do {
            try "probe".write(toFile: path, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            return false // the normal, sandboxed outcome
        }
    }
}
