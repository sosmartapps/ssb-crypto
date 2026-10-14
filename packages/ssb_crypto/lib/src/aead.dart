import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'suite.dart';

/// AES-256-GCM with a versioned header (spec §6.2).
///
/// Output: header(6) | nonce(12) | ciphertext | tag(16)
/// AAD:    header | caller context (e.g. `vault:ID/item:ID`)
///
/// Every item has its own random key, so random 96-bit nonces stay far
/// below the GCM per-key usage limits.
abstract final class Aead {
  static final AesGcm _gcm = AesGcm.with256bits();
  static const keyLength = 32;
  static const nonceLength = 12;
  static const tagLength = 16;
  static const overhead = Suite.headerLength + nonceLength + tagLength;

  /// [nonce] is for known-answer tests ONLY. Production code must leave it
  /// null so a fresh random nonce is drawn: reusing a nonce under one key
  /// breaks AES-GCM. (No production caller passes it; a supplied nonce must
  /// be exactly [nonceLength] bytes.)
  static Future<Uint8List> seal(
    Uint8List key,
    Uint8List plaintext, {
    required ObjectType type,
    List<int> context = const [],
    Uint8List? nonce,
  }) async {
    _checkKey(key);
    if (nonce != null && nonce.length != nonceLength) {
      throw const SsbCryptoException('bad nonce');
    }
    final header = buildHeader(type);
    final n = nonce ?? randomBytes(nonceLength);
    final box = await _gcm.encrypt(
      plaintext,
      secretKey: SecretKeyData(key),
      nonce: n,
      aad: concatBytes([header, context]),
    );
    return concatBytes([header, n, box.cipherText, box.mac.bytes]);
  }

  static Future<Uint8List> open(
    Uint8List key,
    Uint8List blob, {
    required ObjectType type,
    List<int> context = const [],
  }) async {
    _checkKey(key);
    if (blob.length < overhead) throw const SsbCryptoException('decrypt failed');
    final header = Uint8List.sublistView(blob, 0, Suite.headerLength);
    if (!constantTimeEquals(header.sublist(0, 3), Suite.magic) ||
        header[3] != Suite.formatVersion ||
        !Suite.supported.contains(header[4]) ||
        header[5] != type.code) {
      throw const SsbCryptoException('decrypt failed');
    }
    final nonce = Uint8List.sublistView(
        blob, Suite.headerLength, Suite.headerLength + nonceLength);
    final ct = Uint8List.sublistView(
        blob, Suite.headerLength + nonceLength, blob.length - tagLength);
    final tag = Uint8List.sublistView(blob, blob.length - tagLength);
    try {
      final pt = await _gcm.decrypt(
        SecretBox(ct, nonce: nonce, mac: Mac(tag)),
        secretKey: SecretKeyData(key),
        aad: concatBytes([header, context]),
      );
      return Uint8List.fromList(pt);
    } on SecretBoxAuthenticationError {
      throw const SsbCryptoException('decrypt failed');
    }
  }

  static void _checkKey(Uint8List key) {
    if (key.length != keyLength) throw const SsbCryptoException('bad key');
  }
}
