import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'xwing.dart';

/// HPKE (RFC 9180) base mode, single-shot, with:
///   KEM  0x647a  X-Wing (ML-KEM-768 + X25519)
///   KDF  0x0001  HKDF-SHA256
///   AEAD 0x0002  AES-256-GCM
/// This matches the ciphersuite Apple CryptoKit ships on iOS 26
/// (XWingMLKEM768X25519_SHA256_AES_GCM_256), so the native iOS path and this
/// Dart path interoperate. The key schedule is validated against the
/// RFC 9180 test vectors (test/hpke_test.dart).
abstract final class Hpke {
  static const kemXWing = 0x647a;
  static const kdfHkdfSha256 = 0x0001;
  static const aeadAes256Gcm = 0x0002;
  static const _nk = 32, _nn = 12, _nh = 32;

  static final _gcm = AesGcm.with256bits();

  /// Seal [plaintext] to [recipientPublicKey]. Returns enc(1120) || ciphertext.
  static Future<Uint8List> seal(Uint8List recipientPublicKey, Uint8List plaintext,
      {List<int> info = const [], List<int> aad = const []}) async {
    // Snapshot every caller-owned input before the first await (see
    // Aead.seal). encapsulate() and keySchedule() both await before the
    // plaintext is touched.
    final p = Uint8List.fromList(plaintext);
    final inf = Uint8List.fromList(info);
    final ad = Uint8List.fromList(aad);
    try {
      final e = await XWing.encapsulate(recipientPublicKey);
      final HpkeKeySchedule ks;
      try {
        ks = await keySchedule(e.sharedSecret, inf,
            kemId: kemXWing, kdfId: kdfHkdfSha256, aeadId: aeadAes256Gcm);
      } finally {
        wipe(e.sharedSecret);
      }
      try {
        final box = await _gcm.encrypt(p,
            secretKey: SecretKeyData(ks.key), nonce: ks.baseNonce, aad: ad);
        return concatBytes([e.ciphertext, box.cipherText, box.mac.bytes]);
      } finally {
        ks.erase();
      }
    } finally {
      wipe(p);
    }
  }

  static Future<Uint8List> open(Uint8List recipientSecretKey, Uint8List sealed,
      {List<int> info = const [], List<int> aad = const []}) async {
    if (sealed.length < XWing.ciphertextLength + 16) {
      throw const SsbCryptoException('decrypt failed');
    }
    final enc = Uint8List.sublistView(sealed, 0, XWing.ciphertextLength);
    final inf = Uint8List.fromList(info);
    final ad = Uint8List.fromList(aad);
    final ss = await XWing.decapsulate(Uint8List.fromList(enc), recipientSecretKey);
    final HpkeKeySchedule ks;
    try {
      ks = await keySchedule(ss, inf,
          kemId: kemXWing, kdfId: kdfHkdfSha256, aeadId: aeadAes256Gcm);
    } finally {
      wipe(ss);
    }
    final body = Uint8List.sublistView(sealed, XWing.ciphertextLength);
    try {
      final pt = await _gcm.decrypt(
          SecretBox(body.sublist(0, body.length - 16),
              nonce: ks.baseNonce, mac: Mac(body.sublist(body.length - 16))),
          secretKey: SecretKeyData(ks.key),
          aad: ad);
      return Uint8List.fromList(pt);
    } on SecretBoxAuthenticationError {
      throw const SsbCryptoException('decrypt failed');
    } finally {
      ks.erase();
    }
  }

  /// RFC 9180 §5.1 KeySchedule, mode_base (no PSK). Public for test vectors.
  static Future<HpkeKeySchedule> keySchedule(List<int> sharedSecret, List<int> info,
      {required int kemId, required int kdfId, required int aeadId}) async {
    final suiteId = concatBytes([utf8Bytes('HPKE'), u16be(kemId), u16be(kdfId), u16be(aeadId)]);
    final pskIdHash = await _labeledExtract(suiteId, const [], 'psk_id_hash', const []);
    final infoHash = await _labeledExtract(suiteId, const [], 'info_hash', info);
    final context = concatBytes([[0x00], pskIdHash, infoHash]);
    final secret = await _labeledExtract(suiteId, sharedSecret, 'secret', const []);
    try {
      final key = await _labeledExpand(suiteId, secret, 'key', context, _nk);
      final nonce = await _labeledExpand(suiteId, secret, 'base_nonce', context, _nn);
      final exporter = await _labeledExpand(suiteId, secret, 'exp', context, _nh);
      return HpkeKeySchedule(key, nonce, exporter, context);
    } finally {
      wipe(secret);
    }
  }

  static Future<Uint8List> _labeledExtract(
      List<int> suiteId, List<int> salt, String label, List<int> ikm) async {
    final labeled = concatBytes([utf8Bytes('HPKE-v1'), suiteId, utf8Bytes(label), ikm]);
    final mac = await Hmac.sha256().calculateMac(labeled,
        secretKey: SecretKeyData(salt.isEmpty ? Uint8List(_nh) : salt));
    return Uint8List.fromList(mac.bytes);
  }

  static Future<Uint8List> _labeledExpand(List<int> suiteId, List<int> prk,
      String label, List<int> info, int length) async {
    final labeledInfo =
        concatBytes([u16be(length), utf8Bytes('HPKE-v1'), suiteId, utf8Bytes(label), info]);
    // HKDF-Expand (RFC 5869 §2.3)
    final out = <int>[];
    var t = <int>[];
    for (var i = 1; out.length < length; i++) {
      final mac = await Hmac.sha256()
          .calculateMac([...t, ...labeledInfo, i], secretKey: SecretKeyData(prk));
      t = mac.bytes;
      out.addAll(t);
    }
    return Uint8List.fromList(out.sublist(0, length));
  }
}

class HpkeKeySchedule {
  final Uint8List key, baseNonce, exporterSecret, context;
  HpkeKeySchedule(this.key, this.baseNonce, this.exporterSecret, this.context);

  /// Wipes the secret-derived material (key and exporter secret). The base
  /// nonce and context are public values.
  void erase() {
    wipe(key);
    wipe(exporterSecret);
  }
}
