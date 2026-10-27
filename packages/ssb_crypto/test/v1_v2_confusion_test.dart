// SSB-2026-002 Phase 1 (M1): format v1 and format v2 objects must never be
// interchangeable. `Aead.open` / `StreamCipher.decrypt` accept only version
// byte 2; `Aead.openLegacyV1` / `StreamCipher.decryptLegacyV1` accept only
// version byte 1; the header byte and the context encoding both differ.
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

/// Builds a v1 AEAD blob exactly as the pre-Phase-1 `Aead.seal` did:
/// header(v1) | nonce | ct | tag with AAD = header(v1) || context.
Future<Uint8List> sealV1(Uint8List key, Uint8List pt, ObjectType type, List<int> ctx) async {
  final header = buildHeader(type, formatVersion: 1);
  final nonce = randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(pt,
      secretKey: SecretKeyData(key), nonce: nonce, aad: concatBytes([header, ctx]));
  return concatBytes([header, nonce, box.cipherText, box.mac.bytes]);
}

void main() {
  final key = randomBytes(32);
  final pt = utf8Bytes('tier key bytes');

  group('Suite / header', () {
    test('formatVersion is 2, legacy is 1, and the new object types exist', () {
      expect(Suite.formatVersion, 2);
      expect(Suite.legacyFormatVersion, 1);
      expect(ObjectType.manifest.code, 0x05);
      expect(ObjectType.tierExport.code, 0x06);
      expect(buildHeader(ObjectType.item), [0x53, 0x53, 0x42, 2, Suite.v1, 0x01]);
      expect(buildHeader(ObjectType.item, formatVersion: 1), [0x53, 0x53, 0x42, 1, Suite.v1, 0x01]);
    });
  });

  group('Aead v1 / v2 confusion', () {
    test('seal writes version byte 2; open round-trips it', () async {
      final blob = await Aead.seal(key, pt, type: ObjectType.wrappedKey, context: ctx2('t', ['a']));
      expect(blob[3], 2);
      expect(await Aead.open(key, blob, type: ObjectType.wrappedKey, context: ctx2('t', ['a'])), pt);
    });

    test('a v1 blob fails open() and succeeds openLegacyV1()', () async {
      final ctx = utf8Bytes('ssb/v1/tk/ice|vault:v');
      final v1 = await sealV1(key, pt, ObjectType.wrappedKey, ctx);
      expect(v1[3], 1);
      await expectLater(Aead.open(key, v1, type: ObjectType.wrappedKey, context: ctx), throwsSsb);
      expect(await Aead.openLegacyV1(key, v1, type: ObjectType.wrappedKey, context: ctx), pt);
    });

    test('a v2 blob fails openLegacyV1()', () async {
      final ctx = ctx2('tk', ['v', 'ice', u32be(1)]);
      final v2 = await Aead.seal(key, pt, type: ObjectType.wrappedKey, context: ctx);
      await expectLater(Aead.openLegacyV1(key, v2, type: ObjectType.wrappedKey, context: ctx), throwsSsb);
      expect(await Aead.open(key, v2, type: ObjectType.wrappedKey, context: ctx), pt);
    });

    test('rewriting the version byte alone never works in either direction (header is in the AAD)', () async {
      final ctx = ctx2('x', ['y']);
      final v2 = await Aead.seal(key, pt, type: ObjectType.item, context: ctx);
      final asV1 = Uint8List.fromList(v2)..[3] = 1;
      await expectLater(Aead.openLegacyV1(key, asV1, type: ObjectType.item, context: ctx), throwsSsb);
      await expectLater(Aead.open(key, asV1, type: ObjectType.item, context: ctx), throwsSsb);
      final v1 = await sealV1(key, pt, ObjectType.item, ctx);
      final asV2 = Uint8List.fromList(v1)..[3] = 2;
      await expectLater(Aead.open(key, asV2, type: ObjectType.item, context: ctx), throwsSsb);
      await expectLater(Aead.openLegacyV1(key, asV2, type: ObjectType.item, context: ctx), throwsSsb);
      // Other version bytes are refused by both.
      for (final v in [0, 3, 0xff]) {
        final odd = Uint8List.fromList(v2)..[3] = v;
        await expectLater(Aead.open(key, odd, type: ObjectType.item, context: ctx), throwsSsb);
        await expectLater(Aead.openLegacyV1(key, odd, type: ObjectType.item, context: ctx), throwsSsb);
      }
    });

    test('new object types seal and open, and are distinct from the old ones', () async {
      for (final t in [ObjectType.manifest, ObjectType.tierExport]) {
        final blob = await Aead.seal(key, pt, type: t, context: ctx2('m', ['v']));
        expect(blob[5], t.code);
        expect(await Aead.open(key, blob, type: t, context: ctx2('m', ['v'])), pt);
        for (final other in ObjectType.values.where((o) => o != t)) {
          await expectLater(Aead.open(key, blob, type: other, context: ctx2('m', ['v'])), throwsSsb);
        }
      }
    });
  });

  group('ctx2 context encoding', () {
    test("'ssb/v2/' || lp(what) || fields, strings length-prefixed, bytes raw", () {
      final c = ctx2('tk', ['v1', 'ice', u32be(7)]);
      expect(c, concatBytes([
        utf8Bytes('ssb/v2/'),
        u32be(2), utf8Bytes('tk'),
        u32be(2), utf8Bytes('v1'),
        u32be(3), utf8Bytes('ice'),
        [0, 0, 0, 7],
      ]));
      expect(ctx2('m', []), concatBytes([utf8Bytes('ssb/v2/'), u32be(1), utf8Bytes('m')]));
    });

    test('differs from the v1 string contexts and is injective across field boundaries', () {
      expect(ctx2('tk', ['v', 'ice', u32be(1)]), isNot(utf8Bytes('ssb/v1/tk/ice|vault:v')));
      // The classic v1 ambiguity (B4): (slot "a|vault:b", vault "c") vs (slot "a", vault "b|vault:c").
      expect(ctx2('vk', ['c', 'a|vault:b', u32be(1)]), isNot(ctx2('vk', ['b|vault:c', 'a', u32be(1)])));
      expect(ctx2('x', ['ab', 'c']), isNot(ctx2('x', ['a', 'bc'])));
      expect(ctx2('x', ['ab']), isNot(ctx2('xa', ['b'])));
      expect(ctx2('x', ['a', u16be(1)]), isNot(ctx2('x', ['a', u32be(1)])));
    });

    test('a bare int is refused so the width is always explicit', () {
      expect(() => ctx2('x', [1]), throwsArgumentError);
      expect(() => ctx2('x', [1.5]), throwsArgumentError);
    });
  });

  group('StreamCipher v1 / v2', () {
    test('encrypt writes v2; decrypt refuses a v1 header; decryptLegacyV1 refuses v2', () async {
      final data = randomBytes(1000);
      final v2 = await StreamCipher.encrypt(key, data, chunkSize: 256, context: [1]);
      expect(v2[3], 2);
      expect(await StreamCipher.decrypt(key, v2, context: [1]), data);
      await expectLater(StreamCipher.decryptLegacyV1(key, v2, context: [1]), throwsSsb);
      // A header-only downgrade cannot work either (the head is in every chunk's AAD).
      final asV1 = Uint8List.fromList(v2)..[3] = 1;
      await expectLater(StreamCipher.decryptLegacyV1(key, asV1, context: [1]), throwsSsb);
      await expectLater(StreamCipher.decrypt(key, asV1, context: [1]), throwsSsb);
    });

    test('a genuine v1 stream opens only through decryptLegacyV1', () async {
      // Build a one-chunk v1 stream by hand, as the pre-Phase-1 encrypt did.
      final data = randomBytes(40);
      final header = buildHeader(ObjectType.fileStream, formatVersion: 1);
      final prefix = randomBytes(7);
      final head = concatBytes([header, prefix, u32be(64)]);
      final box = await AesGcm.with256bits().encrypt(data,
          secretKey: SecretKeyData(key), nonce: concatBytes([prefix, u32be(0), [1]]), aad: concatBytes([head, [9]]));
      final v1 = concatBytes([head, box.cipherText, box.mac.bytes]);
      expect(await StreamCipher.decryptLegacyV1(key, v1, context: [9]), data);
      await expectLater(StreamCipher.decrypt(key, v1, context: [9]), throwsSsb);
    });
  });
}
