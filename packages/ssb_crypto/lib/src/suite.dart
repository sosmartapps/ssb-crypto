import 'dart:typed_data';

/// Versioned object header, bound into the AEAD associated data so a
/// ciphertext can never be reinterpreted under a different suite, format
/// version or object type (downgrade/confusion protection). See spec §6.1.
///
/// Layout (6 bytes): 'S' 'S' 'B' | formatVersion | suiteId | objectType
abstract final class Suite {
  static const magic = [0x53, 0x53, 0x42]; // "SSB"
  static const formatVersion = 1;

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
  sealedShare(0x04);

  final int code;
  const ObjectType(this.code);
}

Uint8List buildHeader(ObjectType type, {int suite = Suite.v1}) =>
    Uint8List.fromList([...Suite.magic, Suite.formatVersion, suite, type.code]);
