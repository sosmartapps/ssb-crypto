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
    // Shamir.split snapshots the secret itself; the explicit copy here keeps
    // this function correct even if that ever changes.
    final tk = Uint8List.fromList(tierKey);
    final List<Share> shares;
    try {
      shares = await Shamir.split(tk, shares: 3, threshold: 2);
    } finally {
      wipe(tk);
    }
    final s1 = shares[0].toBytes(), s2 = shares[1].toBytes(), s3 = shares[2].toBytes();
    try {
      return ReleaseBundle(
        await KitCode.encode(s1Label, s1),
        await Hpke.seal(beneficiaryPublicKey, s2, info: _info(vaultId, beneficiaryId, tier)),
        await KitCode.encode(s3Label, s3),
      );
    } finally {
      // Both the serialized copies and the Share objects they came from.
      wipe(s1);
      wipe(s2);
      wipe(s3);
      for (final s in shares) {
        s.erase();
      }
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
    final raw1 = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    Uint8List? raw2;
    Share? s1, s2;
    try {
      s1 = Share.fromBytes(raw1);
      raw2 = await Hpke.open(beneficiarySecretKey, sealedServerShare,
          info: _info(vaultId, beneficiaryId, tier));
      s2 = Share.fromBytes(raw2);
      return await Shamir.combine([s1, s2]);
    } finally {
      // Decoded shares are wiped on every exit, including a failed combine.
      wipe(raw1);
      wipe(raw2);
      s1?.erase();
      s2?.erase();
    }
  }

  /// Company-gone path: Beneficiary Kit (S1) + attorney kit (S3), fully
  /// offline (this is what the open-source recovery tool runs).
  static Future<Uint8List> recoverOffline({
    required String beneficiaryKitCode,
    required String attorneyKitCode,
  }) async {
    final raw1 = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    Uint8List? raw3;
    Share? s1, s3;
    try {
      s1 = Share.fromBytes(raw1);
      raw3 = await KitCode.decode(s3Label, attorneyKitCode, payloadLength: _shareLen);
      s3 = Share.fromBytes(raw3);
      return await Shamir.combine([s1, s3]);
    } finally {
      wipe(raw1);
      wipe(raw3);
      s1?.erase();
      s3?.erase();
    }
  }
}
