package dev.devicesentinel.device_sentinel_security

/**
 * Collects the ids of the probes that fired during one check, so a flagged
 * device can be triaged from telemetry. Ids are fixed strings — never paths,
 * package names or anything user-specific.
 */
internal class Signals {
    private val fired = mutableListOf<String>()

    /** Records [id] and returns true, so a probe can `return signals.hit(...)`. */
    fun hit(id: String): Boolean {
        if (id !in fired) fired.add(id)
        return true
    }

    fun toList(): List<String> = fired.toList()
}
