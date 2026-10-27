import 'dart:typed_data';

/// Versioned object header, bound into the AEAD associated data so a
/// ciphertext can never be reinterpreted under a different suite, format
/// version or object type (downgrade/confusion protection). See spec §6.1.
///
/// Layout (6 bytes): 'S' 'S' 'B' | formatVersion | suiteId | objectType
///
/// Format version 2 (SSB-2026-002, Phase 1): every wrap context carries a
/// key-generation epoch and is built with length-prefixed fields
/// (`ctx2`). Version-1 objects are opened ONLY through the explicit legacy
/// entry points (`Aead.openLegacyV1`, `StreamCipher.decryptLegacyV1`,
/// `package:ssb_crypto/legacy_v1.dart`); the normal `open` paths refuse
/// them, so a v1 blob can never be mistaken for a current one.
abstract final class Suite {
  static const magic = [0x53, 0x53, 0x42]; // "SSB"

  /// The format every `seal` writes and every `open` requires.
  static const formatVersion = 2;

  /// The previous format, readable only through the legacy entry points.
  static const legacyFormatVersion = 1;

  /// Suite v1: AES-256-GCM, HKDF-SHA-384, Argon2id, X-Wing HPKE
  /// (ML-KEM-768 + X25519, HKDF-SHA-256, AES-256-GCM), Shamir GF(256).
  static const v1 = 0x01;

  static const supported = {v1};
  static const headerLength = 6;
}

/// What a ciphertext is. Opening with the wrong type fails.
enum ObjectType {
  item(0x01),
  wrappedKey(0x02),
  fileStream(0x03),
  sealedShare(0x04),

  /// The sealed vault manifest (format v2): epochs, slot hashes, item set
  /// hash and the monotonic sequence number. See `manifest.dart`.
  manifest(0x05),

  /// A per-tier export bundle for the server (format v2), with epoch,
  /// export sequence and previous-export hash in its AAD. See `vault.dart`.
  tierExport(0x06);

  final int code;
  const ObjectType(this.code);
}

Uint8List buildHeader(ObjectType type,
        {int suite = Suite.v1, int formatVersion = Suite.formatVersion}) =>
    Uint8List.fromList([...Suite.magic, formatVersion, suite, type.code]);
