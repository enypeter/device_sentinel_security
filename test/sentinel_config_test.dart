import 'package:device_sentinel_security/device_sentinel_security.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  // A real-length SHA-256: 32 bytes.
  final String sha256 = 'ab' * 32;
  final String keytoolSha256 = List<String>.filled(32, 'AB').join(':');

  test('normaliseFingerprint accepts keytool and Play Console formats', () {
    expect(SentinelConfig.normaliseFingerprint('AB:cd:01'), 'abcd01');
    expect(SentinelConfig.normaliseFingerprint(' ab cd 01 '), 'abcd01');
    expect(SentinelConfig.normaliseFingerprint('ABCD01'), 'abcd01');
  });

  test('normaliseFingerprint drops a leading algorithm label', () {
    // keytool -list -v and apksigner verify --print-certs, pasted whole. The
    // label's own hex digits (A, 2, 5, 6) must not end up in the hash.
    expect(
      SentinelConfig.normaliseFingerprint('SHA256: $keytoolSha256'),
      sha256,
    );
    expect(
      SentinelConfig.normaliseFingerprint(
        'Signer #1 certificate SHA-256 digest: $sha256',
      ),
      sha256,
    );
  });

  test('a SHA-1 or truncated entry is invalid; blank entries are not', () {
    final String sha1 = List<String>.filled(20, 'CD').join(':');
    final SentinelConfig config = SentinelConfig(
      androidSigningCertSha256: <String>[keytoolSha256, sha1, '', ':::', 'abc'],
    );

    expect(config.invalidAndroidFingerprints, <String>[sha1, 'abc']);
  });

  test('toChannelArguments normalises hashes and drops blank ones', () {
    final SentinelConfig config = SentinelConfig(
      androidSigningCertSha256: <String>['SHA256: $keytoolSha256', ':::'],
      iosBundleIds: const <String>['com.example.app'],
    );

    expect(config.toChannelArguments(), <String, Object>{
      'androidSigningCertSha256': <String>[sha256],
      'iosBundleIds': <String>['com.example.app'],
    });
  });

  test('one invalid entry skips the Android signature comparison', () {
    // Comparing against the valid rest would flag every install signed by
    // the key whose fingerprint was pasted wrong.
    final SentinelConfig config = SentinelConfig(
      androidSigningCertSha256: <String>[
        keytoolSha256,
        List<String>.filled(20, 'CD').join(':'),
      ],
    );

    expect(config.toChannelArguments()['androidSigningCertSha256'], isEmpty);
  });

  test('defaults to empty identities, which skips the tamper comparison', () {
    expect(const SentinelConfig().toChannelArguments(), <String, Object>{
      'androidSigningCertSha256': <String>[],
      'iosBundleIds': <String>[],
    });
  });
}
