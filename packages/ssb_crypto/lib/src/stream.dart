import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'suite.dart';

/// Chunked file encryption (spec §6.2): the STREAM construction
/// (Hoang, Reyhanitabar, Rogaway, Vizár), as used by age and Tink.
///
/// Each 64 KiB chunk is sealed with AES-256-GCM under
///   nonce = prefix(7) || counter(4, big-endian) || lastFlag(1)
/// and AAD = header || caller context. This detects truncation (missing
/// final chunk), extension (data after the final chunk), reordering and
/// chunk swapping between files.
///
/// Layout: header(6) | prefix(7) | chunkSize(4) | chunk0 | chunk1 | ...
/// where every chunk is ciphertext(<= chunkSize) || tag(16).
abstract final class StreamCipher {
  static const defaultChunkSize = 64 * 1024;
  static const maxChunkSize = 16 * 1024 * 1024;
  static const _prefixLen = 7, _tag = 16;
  static final _gcm = AesGcm.with256bits();

  static Future<Uint8List> encrypt(Uint8List fileKey, Uint8List data,
      {List<int> context = const [], int chunkSize = defaultChunkSize}) async {
    // chunkSize ceiling matches what [decrypt] accepts, so encrypt can never
    // produce a blob its own decrypt rejects. Zero-key tripwire: see
    // Aead._checkKey.
    if (fileKey.length != 32 || isAllZero(fileKey) || chunkSize < 1 || chunkSize > maxChunkSize) {
      throw const SsbCryptoException('bad input');
    }
    final header = buildHeader(ObjectType.fileStream);
    final prefix = randomBytes(_prefixLen);
    final head = concatBytes([header, prefix, u32be(chunkSize)]);
    final aad = concatBytes([head, context]);
    // Key snapshot before the first await (see Aead.seal). [data] is NOT
    // copied -- files can be large -- so callers must keep it intact until
    // this future completes; ItemCrypto.sealFile passes a private padded
    // copy, so nothing outside this package can reach that buffer.
    final k = Uint8List.fromList(fileKey);
    final out = BytesBuilder(copy: false)..add(head);
    final chunks = data.isEmpty ? 1 : (data.length + chunkSize - 1) ~/ chunkSize;
    try {
      for (var i = 0; i < chunks; i++) {
        final start = i * chunkSize;
        final end = (start + chunkSize > data.length) ? data.length : start + chunkSize;
        final box = await _gcm.encrypt(Uint8List.sublistView(data, start, end),
            secretKey: SecretKeyData(k),
            nonce: _nonce(prefix, i, i == chunks - 1),
            aad: aad);
        out..add(box.cipherText)..add(box.mac.bytes);
      }
      return out.toBytes();
    } finally {
      wipe(k);
    }
  }

  /// Decrypts a format-v2 stream. A v1 stream fails with `decrypt failed`;
  /// see [decryptLegacyV1].
  static Future<Uint8List> decrypt(Uint8List fileKey, Uint8List blob,
          {List<int> context = const []}) =>
      _decrypt(fileKey, blob, context: context, formatVersion: Suite.formatVersion);

  /// Decrypts a format-v1 stream (header version byte 1) and nothing else.
  /// For the v1 -> v2 migration (`package:ssb_crypto/legacy_v1.dart`) only.
  static Future<Uint8List> decryptLegacyV1(Uint8List fileKey, Uint8List blob,
          {List<int> context = const []}) =>
      _decrypt(fileKey, blob, context: context, formatVersion: Suite.legacyFormatVersion);

  static Future<Uint8List> _decrypt(Uint8List fileKey, Uint8List blob,
      {required List<int> context, required int formatVersion}) async {
    const headLen = Suite.headerLength + _prefixLen + 4;
    if (fileKey.length != 32 || isAllZero(fileKey) || blob.length < headLen + _tag) {
      throw const SsbCryptoException('decrypt failed');
    }
    final head = Uint8List.sublistView(blob, 0, headLen);
    final expected = buildHeader(ObjectType.fileStream, formatVersion: formatVersion);
    if (!constantTimeEquals(head.sublist(0, Suite.headerLength), expected)) {
      throw const SsbCryptoException('decrypt failed');
    }
    final prefix = head.sublist(Suite.headerLength, Suite.headerLength + _prefixLen);
    final cs = ByteData.sublistView(head, Suite.headerLength + _prefixLen).getUint32(0);
    if (cs < 1 || cs > maxChunkSize) throw const SsbCryptoException('decrypt failed');
    final aad = concatBytes([head, context]);
    final k = Uint8List.fromList(fileKey);
    final out = BytesBuilder(copy: false);
    var off = headLen;
    try {
      for (var i = 0; off < blob.length; i++) {
        final remaining = blob.length - off;
        final isLast = remaining <= cs + _tag;
        final len = isLast ? remaining : cs + _tag;
        if (len < _tag) throw const SsbCryptoException('decrypt failed');
        final chunk = Uint8List.sublistView(blob, off, off + len);
        try {
          final pt = await _gcm.decrypt(
              SecretBox(chunk.sublist(0, len - _tag),
                  nonce: _nonce(prefix, i, isLast), mac: Mac(chunk.sublist(len - _tag))),
              secretKey: SecretKeyData(k),
              aad: aad);
          out.add(pt);
        } on SecretBoxAuthenticationError {
          throw const SsbCryptoException('decrypt failed');
        }
        off += len;
      }
      return out.toBytes();
    } finally {
      wipe(k);
    }
  }

  static Uint8List _nonce(Uint8List prefix, int counter, bool last) =>
      concatBytes([prefix, u32be(counter), [last ? 1 : 0]]);
}
