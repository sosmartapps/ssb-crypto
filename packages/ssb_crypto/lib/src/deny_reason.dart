import 'dart:convert';
import 'dart:typed_data';

import 'bytes.dart';
import 'hpke.dart';

/// The words an owner types when they stop a release, sealed so that only
/// the person who asked can read them.
///
/// Before this, the reason went to the server as plaintext and was handed
/// back to the requester, which made "nothing readable leaves the device"
/// untrue for that one field. Now the owner's device seals it (HPKE, X-Wing
/// + HKDF-SHA256 + AES-256-GCM, the same suite as every other seal here) to
/// the requester's public key, which the owner already holds from enrolling
/// them. The server stores and returns an opaque blob; the requester's
/// device opens it with the secret key printed on their Kit.
///
/// Wire format: `0x01 || enc(1120) || ciphertext || tag(16)`.
///  * The version byte lets the format change without guessing.
///  * The plaintext is `u16be(byteLength) || utf8 || zero padding`, padded up
///    to a multiple of [_bucket] bytes so the blob length reveals only a
///    coarse size, not whether the owner wrote "no" or a paragraph.
///  * HPKE `info` pins the purpose and the AAD pins the request id, so a
///    blob copied onto a different request (by the server, say) fails to
///    open instead of showing the wrong person's words under a new request.
abstract final class DenyReason {
  static const version = 1;
  static const _info = 'ssb/v1/deny-reason';
  static const _bucket = 256;

  /// Longest reason accepted, in characters (matches the old server cap).
  static const maxChars = 500;

  /// 4 bytes is the most one UTF-8 character can take.
  static const maxBytes = maxChars * 4;

  static Uint8List _aad(String requestId) {
    final r = utf8Bytes(requestId);
    return concatBytes([u16be(r.length), r]);
  }

  /// Seals [reason] to [recipientPublicKey] for the request [requestId].
  /// Throws [SsbCryptoException] for an empty reason, one over [maxChars],
  /// or a recipient key that is not a valid X-Wing public key.
  static Future<Uint8List> seal({
    required Uint8List recipientPublicKey,
    required String requestId,
    required String reason,
  }) async {
    final text = utf8Bytes(reason);
    if (reason.isEmpty || reason.runes.length > maxChars || text.length > maxBytes) {
      throw const SsbCryptoException('bad deny reason');
    }
    if (requestId.isEmpty) throw const SsbCryptoException('bad deny reason');
    final total = ((2 + text.length + _bucket - 1) ~/ _bucket) * _bucket;
    final padded = Uint8List(total)
      ..setRange(0, 2, u16be(text.length))
      ..setRange(2, 2 + text.length, text);
    try {
      final sealed = await Hpke.seal(recipientPublicKey, padded,
          info: utf8Bytes(_info), aad: _aad(requestId));
      return concatBytes([
        [version],
        sealed
      ]);
    } finally {
      wipe(padded);
    }
  }

  /// Opens a blob made by [seal]. Any failure (wrong key, wrong request id,
  /// tampering, unknown version, bad padding) is one [SsbCryptoException]
  /// with the same text, so a caller cannot be used as an oracle.
  static Future<String> open({
    required Uint8List recipientSecretKey,
    required String requestId,
    required Uint8List sealed,
  }) async {
    const fail = SsbCryptoException('decrypt failed');
    if (sealed.isEmpty || sealed[0] != version) throw fail;
    final Uint8List pt;
    try {
      pt = await Hpke.open(recipientSecretKey, Uint8List.sublistView(sealed, 1),
          info: utf8Bytes(_info), aad: _aad(requestId));
    } on SsbCryptoException {
      throw fail;
    }
    try {
      if (pt.length < 2 || pt.length % _bucket != 0) throw fail;
      final n = (pt[0] << 8) | pt[1];
      if (n == 0 || 2 + n > pt.length || n > maxBytes) throw fail;
      for (var i = 2 + n; i < pt.length; i++) {
        if (pt[i] != 0) throw fail;
      }
      try {
        return utf8.decode(pt.sublist(2, 2 + n));
      } on FormatException {
        throw fail;
      }
    } finally {
      wipe(pt);
    }
  }
}
