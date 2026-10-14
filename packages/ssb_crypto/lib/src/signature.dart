import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'pq/pq.dart';

/// Hybrid signatures: **Ed25519 + ML-DSA-65** (spec §6.2).
///
/// Both signatures must verify. Used for release tokens issued by the server,
/// beneficiary enrolment records, and the hash-chained audit log — the things
/// a future attacker (quantum or otherwise) must not be able to forge after
/// the fact.
///
/// Wire format (all lengths fixed, so no length-confusion):
///   publicKey  = ed25519 pk(32) || ml-dsa-65 pk(1952)
///   secretKey  = ed25519 seed(32) || ml-dsa-65 sk(4032)
///   signature  = ed25519 sig(64) || ml-dsa-65 sig(3309)
///
/// Signed bytes are domain-separated and unambiguous:
/// `"ssb/v2/sig"` || u16be(len(purpose)) || purpose(UTF-8) || message.
/// The length prefix means no (purpose, message) pair can collide with
/// another, whatever characters the purpose contains.
class HybridKeyPair {
  final Uint8List secretKey, publicKey;
  HybridKeyPair(this.secretKey, this.publicKey);
}

abstract final class HybridSignature {
  static const edPkLen = 32, edSkLen = 32, edSigLen = 64;
  static const dsaPkLen = 1952, dsaSkLen = 4032, dsaSigLen = 3309;
  static const publicKeyLength = edPkLen + dsaPkLen;
  static const secretKeyLength = edSkLen + dsaSkLen;
  static const signatureLength = edSigLen + dsaSigLen;

  static final _ed = Ed25519();

  static Future<HybridKeyPair> generateKeyPair() async {
    final edSeed = randomBytes(edSkLen);
    final edKp = await _ed.newKeyPairFromSeed(edSeed);
    final edPk = (await edKp.extractPublicKey()).bytes;
    final (dsaPk, dsaSk) = MlDsa65.keyGen(randomBytes(32));
    return HybridKeyPair(concatBytes([edSeed, dsaSk]), concatBytes([edPk, dsaPk]));
  }

  static Future<Uint8List> sign(Uint8List secretKey, Uint8List message,
      {required String purpose}) async {
    if (secretKey.length != secretKeyLength) {
      throw const SsbCryptoException('bad signing key');
    }
    final m = _domain(purpose, message);
    final edKp = await _ed.newKeyPairFromSeed(Uint8List.sublistView(secretKey, 0, edSkLen));
    final edSig = await _ed.sign(m, keyPair: edKp);
    final dsaSig = MlDsa65.sign(Uint8List.fromList(Uint8List.sublistView(secretKey, edSkLen)), m);
    if (dsaSig.length != dsaSigLen) throw const SsbCryptoException('sign failed');
    return concatBytes([edSig.bytes, dsaSig]);
  }

  /// Verifies BOTH signatures. A forgery of either algorithm alone fails.
  static Future<bool> verify(Uint8List publicKey, Uint8List message, Uint8List signature,
      {required String purpose}) async {
    if (publicKey.length != publicKeyLength || signature.length != signatureLength) {
      return false;
    }
    final m = _domain(purpose, message);
    final edOk = await _ed.verify(m,
        signature: Signature(Uint8List.sublistView(signature, 0, edSigLen),
            publicKey: SimplePublicKey(Uint8List.sublistView(publicKey, 0, edPkLen),
                type: KeyPairType.ed25519)));
    final dsaOk = MlDsa65.verify(Uint8List.fromList(Uint8List.sublistView(publicKey, edPkLen)), m,
        Uint8List.fromList(Uint8List.sublistView(signature, edSigLen)));
    return edOk && dsaOk;
  }

  static Uint8List _domain(String purpose, Uint8List message) {
    final p = utf8Bytes(purpose);
    if (p.length > 0xffff) throw const SsbCryptoException('purpose too long');
    return concatBytes([utf8Bytes('ssb/v2/sig'), u16be(p.length), p, message]);
  }
}
