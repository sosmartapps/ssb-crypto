// Generic "snapshot before the first await" harness (red team follow-up,
// 2026-10-27; same root cause as SSB-2026-001).
//
// Dart runs an async body synchronously up to its first await. A function
// that reads a caller-owned buffer (or list, or object holding buffers) AFTER
// that point silently uses whatever the caller left in it. This file proves,
// mechanically and for EVERY public Future-returning function of the package
// that takes such an argument, that the result does not depend on what the
// caller does to its arguments after the call has returned its Future:
//
//   run the case with pristine arguments                    -> expected
//   run it again, but right after the call returns its
//   Future, synchronously (a) wipe every argument buffer to
//   zero and clear every argument list/map, (b) flip every
//   argument byte; then await                               -> must equal expected
//
// Cases for seal-style functions (random nonces) are checked through a
// round trip under pristine keys instead of by comparing ciphertext.
//
// REGISTRY: the last group scans lib/ for every public (non-underscore)
// Future-returning function and fails unless it is either a case here or on
// the explicit no-buffer-parameter list below. Add a new async function and
// the build fails until you add a case (or consciously list it).
//
// Private helpers (leading underscore) are not scanned; each is only reached
// through a public function above and was reviewed by hand: _open, _decrypt,
// _expand, _x25519*, _labeledExtract/_labeledExpand (receive private copies),
// _keyCheck (hkdf copies its inputs on entry), _checksum, _seed, _tiers,
// _finishOpen (now fed snapshots by its two callers).
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/legacy_v1.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

Uint8List det(int n, int seed) =>
    Uint8List.fromList([for (var i = 0; i < n; i++) ((i * 37 + seed * 101 + 13) & 0xff) | 1]);

Uint8List cp(Uint8List b) => Uint8List.fromList(b);

String hx(List<int> b) => hexEncode(b);

enum Mode { none, wipe, flip }

/// Hands out tracked copies of pristine fixture buffers and clobbers them on
/// demand. A case calls [run] around the single call under test.
class H {
  H(this.mode);
  final Mode mode;
  final _bufs = <List<int>>[];
  final _maps = <Map<Object?, Object?>>[];
  final _lists = <List<Object?>>[];

  /// A tracked Uint8List copy of [pristine].
  Uint8List t(Uint8List pristine) {
    final c = cp(pristine);
    _bufs.add(c);
    return c;
  }

  /// A tracked growable `List<int>` copy (for `List<int>` parameters).
  List<int> tl(Uint8List pristine) {
    final c = pristine.toList();
    _bufs.add(c);
    return c;
  }

  Map<Tier, Uint8List> tiers(Map<Tier, Uint8List> pristine) {
    final m = {for (final e in pristine.entries) e.key: t(e.value)};
    _maps.add(m);
    return m;
  }

  Map<String, int> intMap(Map<String, int> pristine) {
    final m = Map.of(pristine);
    _maps.add(m);
    return m;
  }

  SealedItem item(SealedItem p) => SealedItem(p.itemId, p.tier, t(p.wrappedItemKey), t(p.body));

  List<SealedItem> items(List<SealedItem> p) {
    final l = [for (final i in p) item(i)];
    _lists.add(l);
    return l;
  }

  List<Share> shares(List<Share> p) {
    final l = [for (final s in p) Share(s.threshold, s.x, s.epoch, t(s.salt), t(s.keyCheck), t(s.y))];
    _lists.add(l);
    return l;
  }

  List<ShareV1> sharesV1(List<ShareV1> p) {
    final l = [for (final s in p) ShareV1(s.threshold, s.x, t(s.keyCheck), t(s.y))];
    _lists.add(l);
    return l;
  }

  void clobber() {
    if (mode == Mode.none) return;
    for (final b in _bufs) {
      for (var i = 0; i < b.length; i++) {
        b[i] = mode == Mode.wipe ? 0 : (b[i] ^ 0xA5);
      }
    }
    if (mode == Mode.wipe) {
      for (final m in _maps) {
        m.clear();
      }
      for (final l in _lists) {
        l.clear();
      }
    }
  }

  /// Starts the call, then clobbers every tracked argument synchronously,
  /// before the caller (or the function's own continuation) can run.
  Future<T> run<T>(Future<T> Function() call) {
    final f = call();
    clobber();
    return f;
  }
}

typedef Case = Future<Object?> Function(H h);

String norm(Object? o) {
  if (o == null) return 'null';
  if (o is List<int>) return 'b:${hx(o)}';
  if (o is List) return '[${o.map(norm).join(',')}]';
  return '$o';
}

Future<String> exec(Case c, Mode m) async {
  try {
    return norm(await c(H(m)));
  } catch (e) {
    return 'THROWS ${e.runtimeType}: $e';
  }
}

/// Modes in which the case's result differs from its pristine result.
Future<List<Mode>> differing(Case c) async {
  final want = await exec(c, Mode.none);
  if (want.startsWith('THROWS')) throw StateError('pristine run threw: $want');
  if (await exec(c, Mode.none) != want) throw StateError('case is not deterministic');
  return [
    for (final m in [Mode.wipe, Mode.flip])
      if (await exec(c, m) != want) m
  ];
}

// ---- v1 builders (copied from legacy_v1_test.dart; format v1 is read-only) --

Future<Uint8List> sealV1(Uint8List key, Uint8List pt, ObjectType type, List<int> ctx) async {
  final header = buildHeader(type, formatVersion: 1);
  final nonce = det(12, 77);
  final box = await AesGcm.with256bits()
      .encrypt(pt, secretKey: SecretKeyData(key), nonce: nonce, aad: concatBytes([header, ctx]));
  return concatBytes([header, nonce, box.cipherText, box.mac.bytes]);
}

Uint8List padV1(Uint8List data) {
  final n = data.length + 4;
  final target = ItemCrypto.padmeLength(n < 256 ? 256 : n);
  return Uint8List(target)..setAll(0, u32be(data.length))..setAll(4, data);
}

int gmul(int a, int b) {
  var p = 0;
  while (b > 0) {
    if (b & 1 == 1) p ^= a;
    a <<= 1;
    if (a & 0x100 != 0) a ^= 0x11b;
    b >>= 1;
  }
  return p;
}

Future<List<Uint8List>> splitV1(Uint8List secret) async {
  final check = await hkdfSha384(ikm: secret, salt: const [], info: 'ssb/v1/share-check', length: 8);
  final c = det(secret.length, 91);
  return [
    for (var x = 1; x <= 3; x++)
      concatBytes([[1, 2, x], check, [for (var i = 0; i < secret.length; i++) secret[i] ^ gmul(c[i], x)]])
  ];
}

/// v1 STREAM: header(v1) | prefix(7) | chunk size(4) | chunks, nonce = prefix | counter | last.
Future<Uint8List> streamV1(Uint8List fk, Uint8List data, List<int> ctx, int cs) async {
  final head = concatBytes([buildHeader(ObjectType.fileStream, formatVersion: 1), det(7, 55), u32be(cs)]);
  final aad = concatBytes([head, ctx]);
  final n = (data.length + cs - 1) ~/ cs;
  final out = BytesBuilder()..add(head);
  for (var i = 0; i < n; i++) {
    final end = (i + 1) * cs > data.length ? data.length : (i + 1) * cs;
    final box = await AesGcm.with256bits().encrypt(data.sublist(i * cs, end),
        secretKey: SecretKeyData(fk),
        nonce: concatBytes([head.sublist(6, 13), u32be(i), [i == n - 1 ? 1 : 0]]),
        aad: aad);
    out..add(box.cipherText)..add(box.mac.bytes);
  }
  return out.toBytes();
}

String ringSummary(VaultKeyring r) {
  final s = [
    r.vaultId,
    hx(r.vaultKey),
    for (final t in Tier.values) '${t.name}:${hx(r.tierKey(t))}:${r.tierEpoch(t)}',
    'seq${r.seq}',
  ].join('|');
  r.dispose();
  return s;
}

String legacySummary(LegacyKeyring r) {
  final s = [r.vaultId, hx(r.vaultKey), for (final t in Tier.values) '${t.name}:${hx(r.tierKey(t))}'].join('|');
  r.dispose();
  return s;
}

/// Public Future-returning functions with no caller-buffer parameter at all
/// (String / int / enum / object arguments only, or no arguments). Each was
/// reviewed by hand; listing one here is a conscious decision.
const noBufferParams = <String>{
  'XWing.installX25519', // takes an X25519 implementation object
  'XWing.generateKeyPair', // no arguments
  'HybridSignature.generateKeyPair', // no arguments
  'KitCode.decode', // String code
  'Unlock.parseSecretKey', // String code
  'ClaimToken.verifier', // String
  'OwnerToken.verifier', // String
  'Release.kitEpoch', // String
  'Release.recoverOffline', // Strings only
  'ReleaseV1.recoverOffline', // Strings only
  'VaultKeyring.createSelfCertifying', // anchor object only
  'VaultKeyring.parseRecoveryKey', // String code
  'VaultKeyring.wrapTierKey', // reads keyring-owned buffers: wipe_race_test.dart (SSB-2026-001)
  'VaultKeyring.commitManifest', // no arguments
  'FreshnessAnchor.lastSeq', // String
  'FreshnessAnchor.commit', // String, int
  'InMemoryAnchor.lastSeq', // String
  'InMemoryAnchor.commit', // String, int
};

void main() {
  // ---- pristine fixtures (never passed to a function directly) -----------
  final key = det(32, 1), pt = det(100, 2), ctx = det(20, 3), nonce = det(12, 4);
  final fk = det(32, 5), data = det(300, 6), salt16 = det(16, 7), pw = det(14, 8);
  final info = det(33, 9), aad = det(17, 10), msg = det(64, 11), sk16 = det(16, 12);
  final vkey = det(32, 13), chNonce = det(24, 14), tk = det(32, 15), tk2 = det(32, 16);
  final kek = det(32, 17), rk = det(32, 18), prevHash = det(32, 19), seed32 = det(32, 20);
  final eseed = det(64, 21), pubKey = det(1216, 22), shareSecret = det(32, 23);

  late XWingKeyPair kp;
  late HybridKeyPair sg;
  late Uint8List aeadBlob, aeadV1Blob, streamBlob, streamV1Blob, hpkeSealed, xwCt, hybridSig;
  late Uint8List ownerPk, ownerSig, denySealed, itemFileWk, itemFileStream, exportCt;
  late String ownerVaultId;
  late List<Share> shamirFx;
  late ReleaseBundle bundle;
  late StoredVault sv;
  late Uint8List svVaultKey;
  late SealedItem item1, item2;
  late TierExport exportFx;
  late VaultManifest manifestFx;
  late Uint8List manifestBlob;
  late Uint8List v1Vk, v1Kek;
  late Map<Tier, Uint8List> v1Wtks;
  late Uint8List v1Wvk;
  late SealedItem v1Item;
  late Uint8List v1FileWk, v1FileStream, v1ExportCt;
  late List<Uint8List> v1Shares;
  late String v1S1, v1S3;
  late Uint8List v1S2;
  late Map<Tier, Uint8List> v1Tks;

  setUpAll(() async {
    kp = await XWing.generateKeyPairDerand(seed32);
    sg = await HybridSignature.generateKeyPair();
    aeadBlob = await Aead.seal(key, pt, type: ObjectType.item, context: ctx);
    aeadV1Blob = await sealV1(key, pt, ObjectType.item, ctx);
    streamBlob = await StreamCipher.encrypt(fk, data, context: ctx, chunkSize: 64);
    streamV1Blob = await streamV1(fk, data, ctx, 64);
    hpkeSealed = await Hpke.seal(kp.publicKey, pt, info: info, aad: aad);
    xwCt = (await XWing.encapsulateDerand(kp.publicKey, eseed)).ciphertext;
    hybridSig = await HybridSignature.sign(sg.secretKey, msg, purpose: 'harness');
    final oi = await OwnerIdentity.derive(vkey);
    ownerPk = oi.publicKey;
    ownerVaultId = oi.vaultId;
    ownerSig = await OwnerIdentity.signChallenge(vaultKey: vkey, vaultId: ownerVaultId, nonce: chNonce);
    denySealed = await DenyReason.seal(recipientPublicKey: kp.publicKey, requestId: 'req-1', reason: 'because');
    shamirFx = await Shamir.split(shareSecret, shares: 3, threshold: 2, epoch: 3);
    bundle = await Release.create(
        vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets, tierKey: tk,
        beneficiaryPublicKey: kp.publicKey, epoch: 3);
    final ov = await OwnerVault.create('vault-h', anchor: InMemoryAnchor(), keks: {'unlock': cp(kek)});
    item1 = await ov.sealItem(Tier.ice, 'i1', 'hello');
    item2 = await ov.sealItem(Tier.secrets, 'i2', 'world');
    sv = await ov.write([item1, item2]);
    svVaultKey = cp(ov.ring.vaultKey);
    manifestFx = ov.ring.manifest;
    manifestBlob = await VaultManifest.seal(svVaultKey, manifestFx);
    itemFileWk = (await ItemCrypto.sealFile(
            vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: 'f1', data: data))
        .$1;
    final f = await ItemCrypto.sealFile(
        vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: 'f1', data: data);
    itemFileWk = f.$1;
    itemFileStream = f.$2;
    exportFx = await TierExportCrypto.seal(
        vaultId: 'v', tier: Tier.ice, tierKey: tk, epoch: 1, seq: 1, prevHash: prevHash, plaintext: pt);
    exportCt = exportFx.ciphertext;
    // v1 fixtures
    v1Vk = det(32, 30);
    v1Kek = det(32, 31);
    v1Tks = {for (final t in Tier.values) t: det(32, 40 + t.index)};
    v1Wvk = await sealV1(v1Kek, v1Vk, ObjectType.wrappedKey, utf8Bytes('ssb/v1/vk/unlock|vault:v1'));
    v1Wtks = {
      for (final t in Tier.values)
        t: await sealV1(v1Vk, v1Tks[t]!, ObjectType.wrappedKey, utf8Bytes('ssb/v1/tk/${t.name}|vault:v1'))
    };
    final ik = det(32, 50);
    v1Item = SealedItem(
        'i1',
        Tier.secrets,
        await sealV1(v1Tks[Tier.secrets]!, ik, ObjectType.wrappedKey,
            utf8Bytes('ssb/v1/ik|vault:v1|tier:secrets|item:i1')),
        await sealV1(ik, padV1(utf8Bytes('old item')), ObjectType.item,
            utf8Bytes('ssb/v1/item|vault:v1|item:i1')));
    final vfk = det(32, 51);
    v1FileWk = await sealV1(v1Tks[Tier.essentials]!, vfk, ObjectType.wrappedKey,
        utf8Bytes('ssb/v1/ik|vault:v1|tier:essentials|item:f1'));
    v1FileStream = await streamV1(vfk, padV1(data), utf8Bytes('ssb/v1/item|vault:v1|item:f1'), 64);
    v1ExportCt = await sealV1(
        tk, utf8Bytes('{"v":1}'), ObjectType.item, utf8Bytes('ssb/v1/tier-export|vault:v|tier:secrets'));
    v1Shares = await splitV1(tk);
    v1S1 = await KitCode.encode('SSB1-BK', v1Shares[0]);
    v1S3 = await KitCode.encode('SSB1-AK', v1Shares[2]);
    v1S2 = await Hpke.seal(kp.publicKey, v1Shares[1], info: ReleaseV1.s2Info('v', 'B', Tier.secrets));
    expect(v1S3, isNotEmpty);
  });

  // ---- one case per public function that takes a caller-owned buffer -------
  final cases = <String, Case>{
    'hkdfSha384': (h) => h.run(() => hkdfSha384(ikm: h.tl(key), salt: h.tl(salt16), info: 'harness', length: 48)),
    'hkdfSha384Bytes': (h) =>
        h.run(() => hkdfSha384Bytes(ikm: h.tl(key), salt: h.tl(salt16), info: h.tl(info), length: 48)),
    'argon2id': (h) => h.run(() => argon2id(h.tl(pw), h.tl(salt16), Argon2Params.testOnly)),
    'Aead.seal': (h) => h.run(() => Aead.seal(h.t(key), h.t(pt),
        type: ObjectType.item, context: h.tl(ctx), nonce: h.t(nonce))),
    'Aead.open': (h) =>
        h.run(() => Aead.open(h.t(key), h.t(aeadBlob), type: ObjectType.item, context: h.tl(ctx))),
    'Aead.openLegacyV1': (h) =>
        h.run(() => Aead.openLegacyV1(h.t(key), h.t(aeadV1Blob), type: ObjectType.item, context: h.tl(ctx))),
    'StreamCipher.encrypt': (h) async {
      final blob = await h.run(() => StreamCipher.encrypt(h.t(fk), h.t(data), context: h.tl(ctx), chunkSize: 64));
      return StreamCipher.decrypt(cp(fk), blob, context: ctx);
    },
    'StreamCipher.decrypt': (h) =>
        h.run(() => StreamCipher.decrypt(h.t(fk), h.t(streamBlob), context: h.tl(ctx))),
    'StreamCipher.decryptLegacyV1': (h) =>
        h.run(() => StreamCipher.decryptLegacyV1(h.t(fk), h.t(streamV1Blob), context: h.tl(ctx))),
    'Hpke.seal': (h) async {
      final sealed = await h.run(
          () => Hpke.seal(h.t(kp.publicKey), h.t(pt), info: h.tl(info), aad: h.tl(aad)));
      return Hpke.open(cp(kp.secretKey), sealed, info: info, aad: aad);
    },
    'Hpke.open': (h) => h.run(
        () => Hpke.open(h.t(kp.secretKey), h.t(hpkeSealed), info: h.tl(info), aad: h.tl(aad))),
    'Hpke.keySchedule': (h) async {
      final ks = await h.run(() => Hpke.keySchedule(h.tl(shareSecret), h.tl(info),
          kemId: Hpke.kemXWing, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm));
      return [ks.key, ks.baseNonce, ks.exporterSecret, ks.context];
    },
    'XWing.generateKeyPairDerand': (h) async {
      final k = await h.run(() => XWing.generateKeyPairDerand(h.t(seed32)));
      return [k.secretKey, k.publicKey];
    },
    'XWing.encapsulate': (h) async {
      final e = await h.run(() => XWing.encapsulate(h.t(kp.publicKey)));
      final back = await XWing.decapsulate(e.ciphertext, cp(kp.secretKey));
      return constantTimeEquals(back, e.sharedSecret) ? 'consistent' : 'INCONSISTENT';
    },
    'XWing.encapsulateDerand': (h) async {
      final e = await h.run(() => XWing.encapsulateDerand(h.t(kp.publicKey), h.t(eseed)));
      return [e.sharedSecret, e.ciphertext];
    },
    'XWing.decapsulate': (h) => h.run(() => XWing.decapsulate(h.t(xwCt), h.t(kp.secretKey))),
    'HybridSignature.sign': (h) async {
      final s = await h.run(() => HybridSignature.sign(h.t(sg.secretKey), h.t(msg), purpose: 'harness'));
      return HybridSignature.verify(cp(sg.publicKey), cp(msg), s, purpose: 'harness');
    },
    'HybridSignature.verify': (h) => h.run(() =>
        HybridSignature.verify(h.t(sg.publicKey), h.t(msg), h.t(hybridSig), purpose: 'harness')),
    'KitCode.encode': (h) => h.run(() => KitCode.encode('SSB1-SK', h.t(sk16))),
    'Unlock.formatSecretKey': (h) => h.run(() => Unlock.formatSecretKey(h.t(sk16))),
    'Unlock.deriveUnlockKey': (h) => h.run(() => Unlock.deriveUnlockKey(
        passphrase: 'correct horse', secretKey: h.t(sk16), accountSalt: h.t(salt16), params: Argon2Params.testOnly)),
    'Unlock.openWithPassphrase': (h) {
      // 'é' has an NFKD form, so a refused first attempt falls through to the
      // legacy-form derivation, which re-reads the Secret Key and salt late.
      var calls = 0;
      return h.run(() => Unlock.openWithPassphrase<String>(
            passphrase: 'café horse',
            secretKey: h.t(sk16),
            accountSalt: h.t(salt16),
            params: Argon2Params.testOnly,
            open: (k) async {
              calls++;
              if (calls == 1) throw const SsbCryptoException('first form refused');
              return hx(k);
            },
          ));
    },
    'ClaimToken.compute': (h) => h.run(() => ClaimToken.compute(beneficiarySecretKey: h.t(key))),
    'OwnerToken.compute': (h) => h.run(() => OwnerToken.compute(vaultId: 'v', vaultKey: h.t(key))),
    'OwnerIdentity.derive': (h) async {
      final o = await h.run(() => OwnerIdentity.derive(h.t(vkey)));
      return [o.publicKey, o.vaultId];
    },
    'OwnerIdentity.signChallenge': (h) => h.run(() =>
        OwnerIdentity.signChallenge(vaultKey: h.t(vkey), vaultId: ownerVaultId, nonce: h.t(chNonce))),
    'OwnerIdentity.verifyChallenge': (h) => h.run(() => OwnerIdentity.verifyChallenge(
        publicKey: h.t(ownerPk), vaultId: ownerVaultId, nonce: h.t(chNonce), signature: h.t(ownerSig))),
    'SafetyNumber.fingerprint': (h) =>
        h.run(() => SafetyNumber.fingerprint(beneficiaryId: 'ben', publicKey: h.t(pubKey))),
    'Shamir.split': (h) async {
      final sh = await h.run(() => Shamir.split(h.t(shareSecret), shares: 3, threshold: 2, epoch: 3));
      return Shamir.combine([sh[2], sh[0]]);
    },
    'Shamir.combine': (h) => h.run(() => Shamir.combine(h.shares(shamirFx.sublist(0, 2)))),
    'Release.create': (h) async {
      final b = await h.run(() => Release.create(
          vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets, tierKey: h.t(tk),
          beneficiaryPublicKey: h.t(kp.publicKey), epoch: 3));
      final off = await Release.recoverOffline(
          beneficiaryKitCode: b.beneficiaryKitCode, attorneyKitCode: b.attorneyKitCode);
      final srv = await Release.recoverWithServerShare(
          vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets, beneficiaryKitCode: b.beneficiaryKitCode,
          sealedServerShare: b.sealedServerShare, beneficiarySecretKey: cp(kp.secretKey));
      return [off.key, off.epoch, srv.key, srv.epoch];
    },
    'Release.recoverWithServerShare': (h) async {
      final r = await h.run(() => Release.recoverWithServerShare(
          vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets, beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: h.t(bundle.sealedServerShare), beneficiarySecretKey: h.t(kp.secretKey)));
      return [r.key, r.epoch];
    },
    'DenyReason.seal': (h) async {
      final s = await h.run(() => DenyReason.seal(
          recipientPublicKey: h.t(kp.publicKey), requestId: 'req-1', reason: 'because'));
      return DenyReason.open(recipientSecretKey: cp(kp.secretKey), requestId: 'req-1', sealed: s);
    },
    'DenyReason.open': (h) => h.run(() => DenyReason.open(
        recipientSecretKey: h.t(kp.secretKey), requestId: 'req-1', sealed: h.t(denySealed))),
    'VaultKeyring.formatRecoveryKey': (h) => h.run(() => VaultKeyring.formatRecoveryKey(h.t(rk))),
    'VaultKeyring.wrapVaultKey': (h) async {
      final ring = VaultKeyring.adopt(vaultId: 'v', vaultKey: cp(vkey), anchor: InMemoryAnchor());
      final blob = await h.run(() => ring.wrapVaultKey(h.t(kek), slot: 'unlock', epoch: 1));
      return Aead.open(cp(kek), blob,
          type: ObjectType.wrappedKey, context: VaultKeyring.vkContext('v', 'unlock', 1));
    },
    'VaultKeyring.open': (h) async => ringSummary(await h.run(() => VaultKeyring.open(
        vaultId: sv.vaultId,
        kek: h.t(kek),
        slot: 'unlock',
        wrappedVaultKey: h.t(sv.wrappedVaultKeys['unlock']!),
        slotEpochs: h.intMap(sv.slotEpochs),
        manifestBlob: h.t(sv.manifest),
        wrappedTierKeys: h.tiers(sv.tiers),
        items: h.items(sv.items),
        anchor: InMemoryAnchor()))),
    'VaultKeyring.fromVaultKey': (h) async => ringSummary(await h.run(() => VaultKeyring.fromVaultKey(
        vaultId: sv.vaultId,
        vaultKey: h.t(svVaultKey),
        manifestBlob: h.t(sv.manifest),
        wrappedTierKeys: h.tiers(sv.tiers),
        items: h.items(sv.items),
        anchor: InMemoryAnchor()))),
    'VaultKeyring.sealManifest': (h) async {
      final ring = VaultKeyring.adopt(vaultId: 'vault-h', vaultKey: cp(svVaultKey), anchor: InMemoryAnchor());
      final blob = await h.run(() => ring.sealManifest(items: h.items(sv.items)));
      final m = await VaultManifest.open(cp(svVaultKey), blob, vaultId: 'vault-h');
      return '${m.itemsHash}|${m.seq}';
    },
    'VaultKeyring.sealTierExport': (h) async {
      final ring = VaultKeyring.adopt(vaultId: 'v', vaultKey: cp(vkey), anchor: InMemoryAnchor());
      final tierKey = cp(ring.tierKey(Tier.ice));
      final ex = await h.run(() => ring.sealTierExport(Tier.ice, h.t(pt)));
      final back = await TierExportCrypto.open(
          vaultId: 'v', tier: Tier.ice, tierKey: tierKey, header: ex.header, ciphertext: ex.ciphertext);
      return [back, ex.header.seq];
    },
    'ItemCrypto.seal': (h) async {
      final it = await h.run(() => ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: h.t(tk), tierEpoch: 1, itemId: 'i', plaintext: h.t(pt)));
      return ItemCrypto.open(vaultId: 'v', tierKey: cp(tk), tierEpoch: 1, item: it);
    },
    'ItemCrypto.open': (h) async {
      final it = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: 'i', plaintext: pt);
      return h.run(() => ItemCrypto.open(vaultId: 'v', tierKey: h.t(tk), tierEpoch: 1, item: h.item(it)));
    },
    'ItemCrypto.rewrapItemKey': (h) async {
      final it = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: 'i', plaintext: pt);
      final re = await h.run(() => ItemCrypto.rewrapItemKey(
          vaultId: 'v', item: h.item(it), oldTierKey: h.t(tk), oldTierEpoch: 1,
          newTier: Tier.secrets, newTierKey: h.t(tk2), newTierEpoch: 2));
      return ItemCrypto.open(vaultId: 'v', tierKey: cp(tk2), tierEpoch: 2, item: re);
    },
    'ItemCrypto.sealFile': (h) async {
      final f = await h.run(() => ItemCrypto.sealFile(
          vaultId: 'v', tier: Tier.ice, tierKey: h.t(tk), tierEpoch: 1, fileId: 'f1', data: h.t(data)));
      return ItemCrypto.openFile(
          vaultId: 'v', tier: Tier.ice, tierKey: cp(tk), tierEpoch: 1, fileId: 'f1', wrappedKey: f.$1, stream: f.$2);
    },
    'ItemCrypto.openFile': (h) => h.run(() => ItemCrypto.openFile(
        vaultId: 'v', tier: Tier.ice, tierKey: h.t(tk), tierEpoch: 1, fileId: 'f1',
        wrappedKey: h.t(itemFileWk), stream: h.t(itemFileStream))),
    'TierExportCrypto.seal': (h) async {
      final ex = await h.run(() => TierExportCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: h.t(tk), epoch: 1, seq: 1, prevHash: h.t(prevHash),
          plaintext: h.t(pt)));
      return TierExportCrypto.open(
          vaultId: 'v', tier: Tier.ice, tierKey: cp(tk), header: ex.header, ciphertext: ex.ciphertext);
    },
    'TierExportCrypto.open': (h) => h.run(() => TierExportCrypto.open(
        vaultId: 'v', tier: Tier.ice, tierKey: h.t(tk), header: exportFx.header, ciphertext: h.t(exportCt))),
    'VaultManifest.seal': (h) async {
      final blob = await h.run(() => VaultManifest.seal(h.t(svVaultKey), manifestFx));
      final m = await VaultManifest.open(cp(svVaultKey), blob, vaultId: manifestFx.vaultId);
      return '${m.itemsHash}|${m.seq}|${m.vaultId}';
    },
    'VaultManifest.open': (h) async {
      final m = await h.run(() => VaultManifest.open(h.t(svVaultKey), h.t(manifestBlob), vaultId: manifestFx.vaultId));
      return '${m.itemsHash}|${m.seq}|${m.vaultId}';
    },
    'ShamirV1.combine': (h) => h.run(() => ShamirV1.combine(
        h.sharesV1([ShareV1.fromBytes(v1Shares[0]), ShareV1.fromBytes(v1Shares[2])]))),
    'ReleaseV1.recoverWithServerShare': (h) => h.run(() => ReleaseV1.recoverWithServerShare(
        vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets, beneficiaryKitCode: v1S1,
        sealedServerShare: h.t(v1S2), beneficiarySecretKey: h.t(kp.secretKey))),
    'VaultKeyringV1.open': (h) async => legacySummary(await h.run(() => VaultKeyringV1.open(
        vaultId: 'v1', kek: h.t(v1Kek), slot: 'unlock', wrappedVaultKey: h.t(v1Wvk),
        wrappedTierKeys: h.tiers(v1Wtks)))),
    'VaultKeyringV1.fromVaultKey': (h) async => legacySummary(await h.run(() => VaultKeyringV1.fromVaultKey(
        vaultId: 'v1', vaultKey: h.t(v1Vk), wrappedTierKeys: h.tiers(v1Wtks)))),
    'ItemCryptoV1.open': (h) => h.run(() => ItemCryptoV1.open(
        vaultId: 'v1', tierKey: h.t(v1Tks[Tier.secrets]!), item: h.item(v1Item))),
    'ItemCryptoV1.openFile': (h) => h.run(() => ItemCryptoV1.openFile(
        vaultId: 'v1', tier: Tier.essentials, tierKey: h.t(v1Tks[Tier.essentials]!), fileId: 'f1',
        wrappedKey: h.t(v1FileWk), stream: h.t(v1FileStream))),
    'TierExportV1.open': (h) => h.run(() => TierExportV1.open(
        vaultId: 'v', tier: Tier.secrets, tierKey: h.t(tk), ciphertext: h.t(v1ExportCt))),
  };

  group('harness self-test: it must have teeth', () {
    test('detects a function that reads its buffer after an await', () async {
      Future<String> buggy(Uint8List b) async {
        await Future<void>.delayed(Duration.zero);
        return hx(b);
      }

      expect(await differing((h) => h.run(() => buggy(h.t(det(8, 1))))), [Mode.wipe, Mode.flip]);
    });

    test('detects a list read after an await', () async {
      Future<int> buggy(List<Uint8List> l) async {
        await Future<void>.delayed(Duration.zero);
        return l.length;
      }

      Future<Object?> c(H h) {
        final l = [h.t(det(8, 1))];
        h._lists.add(l);
        return h.run(() => buggy(l));
      }

      expect(await differing(c), [Mode.wipe]);
    });

    test('accepts a function that snapshots first', () async {
      Future<String> good(Uint8List b) async {
        final c = cp(b);
        await Future<void>.delayed(Duration.zero);
        return hx(c);
      }

      expect(await differing((h) => h.run(() => good(h.t(det(8, 1))))), isEmpty);
    });
  });

  group('every public async function ignores what the caller does to its arguments after the call', () {
    for (final e in cases.entries) {
      test(e.key, () async {
        final bad = await differing(e.value);
        expect(bad, isEmpty,
            reason: '${e.key}: result changed when the caller wiped/overwrote its arguments '
                'right after the call returned its Future (modes: ${bad.map((m) => m.name).join(', ')})');
      }, timeout: const Timeout(Duration(minutes: 3)));
    }
  });

  group('registry (a new async function must be added here or the build fails)', () {
    final head = RegExp(r'Future<.*?>\s+([A-Za-z]\w*)\s*(?:<[^>(]*>)?\(');
    final klass = RegExp(
        r'^(?:abstract\s+interface\s+class|abstract\s+final\s+class|final\s+class|abstract\s+class|mixin|class)\s+(\w+)');
    final bufferish = RegExp(r'Uint8List|List<int>|List<Share|SealedItem|VaultManifest|Map<Tier|Share\b|TierExportHeader');

    /// name -> parameter text, for every public Future-returning declaration.
    Map<String, String> discover() {
      final out = <String, String>{};
      final files = Directory('lib')
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.endsWith('.dart'))
          .toList()
        ..sort((a, b) => a.path.compareTo(b.path));
      for (final f in files) {
        final src = f.readAsStringSync();
        final lines = src.split('\n');
        var cls = '';
        var offset = 0;
        for (final line in lines) {
          final trimmed = line.trimLeft();
          final km = klass.firstMatch(line);
          if (km != null) cls = km.group(1)!;
          if (line.startsWith('}')) cls = '';
          if (!trimmed.startsWith('//') && !trimmed.startsWith('typedef')) {
            for (final m in head.allMatches(line)) {
              final name = m.group(1)!;
              if (name == 'Function' || name.startsWith('_')) continue;
              var i = offset + m.end - 1, depth = 0, j = i;
              for (; j < src.length; j++) {
                if (src[j] == '(') depth++;
                if (src[j] == ')' && --depth == 0) break;
              }
              out[cls.isEmpty ? name : '$cls.$name'] = src.substring(i, j + 1);
            }
          }
          offset += line.length + 1;
        }
      }
      return out;
    }

    test('every public Future-returning function is a case or on the no-buffer list', () {
      final found = discover();
      final withBuffers = {for (final e in found.entries) if (bufferish.hasMatch(e.value)) e.key};
      final without = found.keys.toSet().difference(withBuffers);
      // ignore: avoid_print
      print('public async functions with caller-buffer parameters (${withBuffers.length}):\n  '
          '${(withBuffers.toList()..sort()).join('\n  ')}\n'
          'public async functions with no buffer parameter (${without.length}):\n  '
          '${(without.toList()..sort()).join('\n  ')}');
      expect(withBuffers.difference(cases.keys.toSet()), isEmpty,
          reason: 'async function taking a caller buffer but no snapshot-before-await case above');
      expect(cases.keys.toSet().difference(withBuffers), isEmpty,
          reason: 'case for a function that no longer exists or no longer takes a buffer');
      expect(without.difference(noBufferParams), isEmpty,
          reason: 'new async function with no recognised buffer parameter: review it, then list it in noBufferParams');
      expect(noBufferParams.difference(without), isEmpty,
          reason: 'stale noBufferParams entry');
    });
  });
}
