import Foundation

/// Collects the ids of the probes that fired during one check, so a flagged
/// device can be triaged from telemetry. Ids are fixed strings — never paths
/// or anything user-specific.
final class Signals {
    private(set) var fired: [String] = []

    /// Records `id` and returns true, so a probe can `return signals.hit(...)`.
    @discardableResult
    func hit(_ id: String) -> Bool {
        if !fired.contains(id) { fired.append(id) }
        return true
    }
}
