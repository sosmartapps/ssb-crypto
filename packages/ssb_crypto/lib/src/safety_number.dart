import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// In-person key verification (spec §6.3, key-substitution defense).
///
/// The owner scans a QR on the beneficiary's phone (or compares the digits)
/// before a beneficiary is marked verified. A malicious server that swapped
/// in its own public key would produce a different number.
///
/// Like Signal's safety numbers: 5200 iterations of SHA-512 over a
/// versioned, domain-separated input make grinding for a lookalike number
/// expensive; 30 bytes are rendered as 12 groups of 5 digits.
abstract final class SafetyNumber {
  static const _iterations = 5200;

  static Future<Uint8List> fingerprint(
      {required String beneficiaryId, required Uint8List publicKey}) async {
    final id = utf8Bytes(beneficiaryId);
    // Snapshot the key before the first await (see Aead.seal): it is mixed
    // into every one of the 5200 rounds, so a caller that overwrites its
    // buffer mid-computation must not be able to change the number.
    final pk = Uint8List.fromList(publicKey);
    try {
      var h = concatBytes([u16be(1), utf8Bytes('ssb/v1/safety'), u16be(id.length), id, pk]);
      final sha = Sha512();
      for (var i = 0; i < _iterations; i++) {
        h = Uint8List.fromList((await sha.hash(concatBytes([h, pk]))).bytes);
      }
      return Uint8List.fromList(h.sublist(0, 30));
    } finally {
      wipe(pk);
    }
  }

  /// "12345 67890 ..." (60 digits).
  static String digits(Uint8List fp) {
    final groups = <String>[];
    for (var i = 0; i < 30; i += 5) {
      var v = 0;
      for (var j = 0; j < 5; j++) {
        v = v * 256 + fp[i + j];
      }
      final n = v % 10000000000; // 10 digits per 5 bytes
      final s = n.toString().padLeft(10, '0');
      groups..add(s.substring(0, 5))..add(s.substring(5));
    }
    return groups.join(' ');
  }

  /// Constant-time match of a scanned QR fingerprint.
  static bool matches(Uint8List a, Uint8List b) => constantTimeEquals(a, b);
}
