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
    // Snapshot every input BEFORE the first await. An async body runs
    // synchronously only up to its first await; a caller that wipes or
    // rotates its buffer while this call is pending (rotateTier()/dispose()
    // during an in-flight wrap, report SSB-2026-001) must not be able to
    // turn the sealed value into zeros without an error. The copies are
    // wiped as soon as the cipher is done with them.
    final k = Uint8List.fromList(key);
    final p = Uint8List.fromList(plaintext);
    final aad = concatBytes([header, context]);
    try {
      final box = await _gcm.encrypt(
        p,
        secretKey: SecretKeyData(k),
        nonce: n,
        aad: aad,
      );
      return concatBytes([header, n, box.cipherText, box.mac.bytes]);
    } finally {
      wipe(k);
      wipe(p);
    }
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
    // Key snapshot for the same reason as in [seal]. The ciphertext is not
    // copied: a caller mutating it mid-flight can only make authentication
    // fail, never make it succeed on different bytes.
    final k = Uint8List.fromList(key);
    final aad = concatBytes([header, context]);
    try {
      final pt = await _gcm.decrypt(
        SecretBox(ct, nonce: nonce, mac: Mac(tag)),
        secretKey: SecretKeyData(k),
        aad: aad,
      );
      return Uint8List.fromList(pt);
    } on SecretBoxAuthenticationError {
      throw const SsbCryptoException('decrypt failed');
    } finally {
      wipe(k);
    }
  }

  static void _checkKey(Uint8List key) {
    if (key.length != keyLength) throw const SsbCryptoException('bad key');
    // Tripwire: a real 256-bit key is all zeros with probability 2^-256.
    // The only way one shows up here is a buffer that was wiped before (or
    // while) it was used, so fail loudly instead of sealing under a public
    // key (report SSB-2026-001 and its follow-up audit).
    if (isAllZero(key)) throw const SsbCryptoException('bad key');
  }
}
