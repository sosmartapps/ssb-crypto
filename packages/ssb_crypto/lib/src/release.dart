import 'dart:typed_data';

import 'bytes.dart';
import 'hpke.dart';
import 'kit_code.dart';
import 'shamir.dart';
import 'vault.dart';

/// Two-key release (spec §6.3). For each beneficiary and tier, the tier key
/// is split 2-of-3:
///
///   S1  printed Beneficiary Kit, handed over at enrollment
///   S2  HPKE-sealed to the beneficiary's X-Wing key and stored on the
///       server, which withholds it until the release timer expires.
///       The server cannot read it.
///   S3  optional printed kit for an attorney / safe-deposit box, so the
///       vault still opens if So Smart Apps no longer exists.
///
/// No single party (server, beneficiary, attorney) can recover the tier key.
class ReleaseBundle {
  final String beneficiaryKitCode; // S1
  final Uint8List sealedServerShare; // S2 (store on server)
  final String attorneyKitCode; // S3
  ReleaseBundle(this.beneficiaryKitCode, this.sealedServerShare, this.attorneyKitCode);
}

abstract final class Release {
  static const s1Label = 'SSB1-BK';
  static const s3Label = 'SSB1-AK';
  static const _shareLen = 3 + 8 + 32;

  /// HPKE info for S2: label || len-prefixed vaultId || len-prefixed
  /// beneficiaryId || len-prefixed tier. Length prefixes make the encoding
  /// injective (ids containing delimiters cannot collide). Public so tests
  /// can open an S2 independently.
  static List<int> s2Info(String vaultId, String beneficiaryId, Tier t) =>
      concatBytes([
        utf8Bytes('ssb/v2/s2'),
        lengthPrefixed(vaultId),
        lengthPrefixed(beneficiaryId),
        lengthPrefixed(t.name),
      ]);

  static List<int> _info(String vaultId, String beneficiaryId, Tier t) =>
      s2Info(vaultId, beneficiaryId, t);

  static Future<ReleaseBundle> create({
    required String vaultId,
    required String beneficiaryId,
    required Tier tier,
    required Uint8List tierKey,
    required Uint8List beneficiaryPublicKey,
  }) async {
    final shares = await Shamir.split(tierKey, shares: 3, threshold: 2);
    final s1 = shares[0].toBytes(), s2 = shares[1].toBytes(), s3 = shares[2].toBytes();
    try {
      return ReleaseBundle(
        await KitCode.encode(s1Label, s1),
        await Hpke.seal(beneficiaryPublicKey, s2, info: _info(vaultId, beneficiaryId, tier)),
        await KitCode.encode(s3Label, s3),
      );
    } finally {
      wipe(s1);
      wipe(s2);
      wipe(s3);
    }
  }

  /// Normal path: Beneficiary Kit (S1) + server share (S2) after the wait.
  static Future<Uint8List> recoverWithServerShare({
    required String vaultId,
    required String beneficiaryId,
    required Tier tier,
    required String beneficiaryKitCode,
    required Uint8List sealedServerShare,
    required Uint8List beneficiarySecretKey,
  }) async {
    final s1 = Share.fromBytes(
        await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen));
    final s2 = Share.fromBytes(await Hpke.open(beneficiarySecretKey, sealedServerShare,
        info: _info(vaultId, beneficiaryId, tier)));
    return Shamir.combine([s1, s2]);
  }

  /// Company-gone path: Beneficiary Kit (S1) + attorney kit (S3), fully
  /// offline (this is what the open-source recovery tool runs).
  static Future<Uint8List> recoverOffline({
    required String beneficiaryKitCode,
    required String attorneyKitCode,
  }) async {
    final s1 = Share.fromBytes(
        await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen));
    final s3 = Share.fromBytes(
        await KitCode.decode(s3Label, attorneyKitCode, payloadLength: _shareLen));
    return Shamir.combine([s1, s3]);
  }
}
