import 'package:flutter/foundation.dart';

/// The identities a release build is expected to carry.
///
/// Nothing here is a secret: certificate hashes and bundle identifiers are
/// public. They only let the native tamper check tell "our build" from "a
/// re-signed copy". Leave a list empty to skip that part of the check.
@immutable
class SentinelConfig {
  const SentinelConfig({
    this.androidSigningCertSha256 = const <String>[],
    this.iosBundleIds = const <String>[],
  });

  /// SHA-256 fingerprints of every certificate allowed to sign the Android
  /// app — typically the upload key **and** the Play App Signing key.
  ///
  /// Any format `keytool`, `apksigner` or the Play Console prints is accepted
  /// (`SHA256: AB:CD:...`, `AB:CD:...` or `abcd...`); it is normalised before
  /// it reaches native. A SHA-1 or otherwise malformed entry makes the whole
  /// list unreliable, so the Android signature check is then skipped and every
  /// report carries the `config.invalid_fingerprint` signal; see
  /// [invalidAndroidFingerprints].
  final List<String> androidSigningCertSha256;

  /// Bundle identifiers the iOS app may run under (one per flavor/scheme).
  final List<String> iosBundleIds;

  /// Entries of [androidSigningCertSha256] that do not normalise to a SHA-256
  /// fingerprint (64 hex digits): a SHA-1, a truncated paste, a typo. Entries
  /// with no hex digits at all (an unset build variable) are ignored, not
  /// invalid.
  List<String> get invalidAndroidFingerprints =>
      androidSigningCertSha256.where((String fingerprint) {
        final String hash = normaliseFingerprint(fingerprint);
        return hash.isNotEmpty && !_sha256Hex.hasMatch(hash);
      }).toList();

  /// The arguments sent to the native side.
  Map<String, Object> toChannelArguments() => <String, Object>{
    // One malformed entry means the allow-list no longer covers every key
    // that legitimately signs the app (say the Play signing key was pasted
    // as SHA-1). Comparing against the rest would brand every store install
    // tampered, so the comparison is skipped instead.
    'androidSigningCertSha256': invalidAndroidFingerprints.isEmpty
        ? androidSigningCertSha256
              .map(normaliseFingerprint)
              .where((String hash) => hash.isNotEmpty)
              .toList()
        : const <String>[],
    'iosBundleIds': iosBundleIds,
  };

  /// Lower-case hex without separators or a leading algorithm label, so
  /// `SHA256: AB:CD`, `AB:CD` and `abcd` compare equal.
  static String normaliseFingerprint(String fingerprint) => fingerprint
      .replaceFirst(_algorithmLabel, '')
      .replaceAll(_nonHex, '')
      .toLowerCase();

  // `keytool` prints "SHA256: AB:…", apksigner "… SHA-256 digest: ab…". The
  // label must go before the non-hex strip, or its `A`, `2`, `5`, `6` would
  // be kept as part of the hash. Hex digits never include `s` or `h`, so
  // this cannot eat into a bare fingerprint.
  static final RegExp _algorithmLabel = RegExp(
    r'^.*sha-?256[^:]*:',
    caseSensitive: false,
  );
  static final RegExp _nonHex = RegExp('[^0-9a-fA-F]');
  static final RegExp _sha256Hex = RegExp(r'^[0-9a-f]{64}$');
}
