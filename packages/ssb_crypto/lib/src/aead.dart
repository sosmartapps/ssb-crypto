import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'suite.dart';

/// AES-256-GCM with a versioned header (spec §6.2).
///
/// Output: header(6) | nonce(12) | ciphertext | tag(16)
/// AAD:    header | caller context (a `ctx2(...)` value for format v2)
///
/// Every item has its own random key, so random 96-bit nonces stay far
/// below the GCM per-key usage limits.
///
/// Format versions: [seal] always writes [Suite.formatVersion] (2) and
/// [open] accepts only that. Objects written by the previous format are
/// opened through [openLegacyV1] alone, which in turn accepts only version
/// byte 1 -- the two never overlap, so a v1 blob cannot be presented as a
/// v2 one or vice versa (SSB-2026-002, design D8).
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
    // A caller-supplied nonce is copied too: it is written into the output
    // after the cipher has yielded.
    final n = nonce == null ? randomBytes(nonceLength) : Uint8List.fromList(nonce);
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

  /// Opens a format-v2 object. A blob whose header carries any other format
  /// version (a v1 object included) fails with `decrypt failed`.
  static Future<Uint8List> open(
    Uint8List key,
    Uint8List blob, {
    required ObjectType type,
    List<int> context = const [],
  }) =>
      _open(key, blob, type: type, context: context, formatVersion: Suite.formatVersion);

  /// Opens a format-v1 object (header version byte 1) and nothing else.
  ///
  /// For the v1 -> v2 migration and `package:ssb_crypto/legacy_v1.dart`
  /// only. The caller supplies the v1 context string; this method does not
  /// know or check what the context means, it only refuses non-v1 headers.
  static Future<Uint8List> openLegacyV1(
    Uint8List key,
    Uint8List blob, {
    required ObjectType type,
    List<int> context = const [],
  }) =>
      _open(key, blob, type: type, context: context, formatVersion: Suite.legacyFormatVersion);

  static Future<Uint8List> _open(
    Uint8List key,
    Uint8List blob, {
    required ObjectType type,
    required List<int> context,
    required int formatVersion,
  }) async {
    _checkKey(key);
    if (blob.length < overhead) throw const SsbCryptoException('decrypt failed');
    // Snapshot the whole blob: the header is checked here, but the nonce,
    // ciphertext and tag views are read by the cipher after it has yielded,
    // and a mid-flight change must not turn into a different (or merely
    // inconsistent) result.
    final b = Uint8List.fromList(blob);
    final header = Uint8List.sublistView(b, 0, Suite.headerLength);
    if (!constantTimeEquals(header.sublist(0, 3), Suite.magic) ||
        header[3] != formatVersion ||
        !Suite.supported.contains(header[4]) ||
        header[5] != type.code) {
      throw const SsbCryptoException('decrypt failed');
    }
    final nonce = Uint8List.sublistView(
        b, Suite.headerLength, Suite.headerLength + nonceLength);
    final ct = Uint8List.sublistView(
        b, Suite.headerLength + nonceLength, b.length - tagLength);
    final tag = Uint8List.sublistView(b, b.length - tagLength);
    // Key snapshot for the same reason as in [seal].
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
