package dev.devicesentinel.device_sentinel_security

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * Signing-certificate check: the app is "tampered" when none of its signing
 * certificates is in the host's allow-list.
 *
 * Skipped in debug builds of this plugin. That is decided by how the APK was
 * BUILT (BuildConfig.DEBUG), never by the runtime debuggable flag, which a
 * repackager can switch on in a re-signed APK.
 */
internal object TamperCheck {
    @Volatile private var cachedFor: Set<String>? = null
    @Volatile private var cachedTampered = false

    fun isTampered(context: Context, allowedSha256: Set<String>, signals: Signals): Boolean {
        if (BuildConfig.DEBUG) return false
        return check(allowedSha256, signals) {
            signingCertificates(context).map { it.toByteArray() }
        }
    }

    /** The comparison and its cache, apart from Android, for unit tests. */
    internal fun check(
        allowedSha256: Set<String>,
        signals: Signals,
        readCertificates: () -> List<ByteArray>
    ): Boolean {
        if (allowedSha256.isEmpty()) return false
        // The APK signature cannot change while the process lives.
        if (cachedFor == allowedSha256) {
            if (cachedTampered) signals.hit("tamper.signature")
            return cachedTampered
        }
        val tampered = try {
            readCertificates().none { sha256Hex(it) in allowedSha256 }
        } catch (_: Exception) {
            // Unverifiable: treat as tampered, as a stripped signature would
            // be, but only for this check. A transient PackageManager failure
            // (a binder hiccup under memory pressure) must not brand the rest
            // of the process tampered, so nothing is cached.
            return signals.hit("tamper.unverifiable")
        }
        cachedTampered = tampered
        cachedFor = allowedSha256
        if (tampered) signals.hit("tamper.signature")
        return tampered
    }

    private fun signingCertificates(context: Context): Array<Signature> {
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
                )
            } else {
                pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            }
            val signingInfo = info.signingInfo ?: return emptyArray()
            // History covers key rotation: a re-signer cannot forge the
            // rotation proof, so any match in it is ours.
            return if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            } ?: emptyArray()
        }
        @Suppress("DEPRECATION")
        val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        @Suppress("DEPRECATION")
        return info.signatures ?: emptyArray()
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
