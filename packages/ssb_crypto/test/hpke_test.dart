import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  final v = jsonDecode(File(
          'test/vectors/hpke_rfc9180_base_x25519_sha256_aes256.json')
      .readAsStringSync()) as Map<String, dynamic>;

  test('RFC 9180 key schedule vector (HKDF-SHA256, AES-256-GCM)', () async {
    final ks = await Hpke.keySchedule(
        hexDecode(v['shared_secret']), hexDecode(v['info']),
        kemId: v['kem_id'], kdfId: v['kdf_id'], aeadId: v['aead_id']);
    expect(hexEncode(ks.context), v['key_schedule_context']);
    expect(hexEncode(ks.key), v['key']);
    expect(hexEncode(ks.baseNonce), v['base_nonce']);
    expect(hexEncode(ks.exporterSecret), v['exporter_secret']);
    // First encryption (seq 0) uses base_nonce directly.
    final e0 = (v['encryptions'] as List).first as Map<String, dynamic>;
    final box = await AesGcm.with256bits().encrypt(hexDecode(e0['pt']),
        secretKey: SecretKeyData(ks.key), nonce: hexDecode(e0['nonce']), aad: hexDecode(e0['aad']));
    expect(hexEncode([...box.cipherText, ...box.mac.bytes]), e0['ct']);
    expect(e0['nonce'], v['base_nonce']);
  });

  test('X-Wing HPKE seal/open round trip with info and aad', () async {
    final kp = await XWing.generateKeyPair();
    final msg = Uint8List.fromList(utf8.encode('tier-2 share'));
    final sealed = await Hpke.seal(kp.publicKey, msg, info: utf8.encode('ctx'), aad: [1, 2]);
    expect(await Hpke.open(kp.secretKey, sealed, info: utf8.encode('ctx'), aad: [1, 2]), msg);
  });

  test('HPKE rejects wrong recipient, wrong info, wrong aad, tampering', () async {
    final kp = await XWing.generateKeyPair();
    final other = await XWing.generateKeyPair();
    final sealed = await Hpke.seal(kp.publicKey, Uint8List(32), info: [9], aad: [7]);
    Future<void> bad(Future<Uint8List> f) =>
        expectLater(f, throwsA(isA<SsbCryptoException>()));
    await bad(Hpke.open(other.secretKey, sealed, info: [9], aad: [7]));
    await bad(Hpke.open(kp.secretKey, sealed, info: [8], aad: [7]));
    await bad(Hpke.open(kp.secretKey, sealed, info: [9], aad: [6]));
    final t = Uint8List.fromList(sealed)..[sealed.length - 1] ^= 1;
    await bad(Hpke.open(kp.secretKey, t, info: [9], aad: [7]));
  });
}
