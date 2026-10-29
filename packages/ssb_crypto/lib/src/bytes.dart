import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/shake.dart';

/// Every failure surfaces as this one type with a generic message, so error
/// text never becomes an oracle (which check failed stays internal).
class SsbCryptoException implements Exception {
  final String message;
  const SsbCryptoException(this.message);
  @override
  String toString() => 'SsbCryptoException: $message';
}

final Random _rng = Random.secure();

/// Cryptographically secure random bytes from the OS CSPRNG.
Uint8List randomBytes(int length) {
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = _rng.nextInt(256);
  }
  return out;
}

/// Constant-time comparison (time depends only on length).
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Uint8List concatBytes(List<List<int>> parts) {
  final total = parts.fold<int>(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setAll(off, p);
    off += p.length;
  }
  return out;
}

/// Best-effort wipe. Dart's GC may have copied the buffer; long-lived
/// secrets should stay in native memory where possible (see spec §6.4).
void wipe(Uint8List? b) => b?.fillRange(0, b.length, 0);

/// True when every byte is zero (constant time in the length). Used as a
/// tripwire for key material that was wiped before it was used.
bool isAllZero(List<int> b) {
  var acc = 0;
  for (final x in b) {
    acc |= x;
  }
  return acc == 0;
}

/// Big-endian 2-byte integer. Throws [SsbCryptoException] outside 0..0xffff:
/// a silent `& 0xff` truncation would make 65536 encode like 0 and -1 like
/// 65535, so two different epochs or lengths could share one context (red
/// team 2026-10-26, sibling of SSB-2026-004 -- ambiguous encoding).
Uint8List u16be(int v) {
  if (v < 0 || v > 0xffff) throw const SsbCryptoException('integer out of range');
  return Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);
}

/// Big-endian 4-byte integer. Throws [SsbCryptoException] outside
/// 0..0xffffffff (see [u16be]).
Uint8List u32be(int v) {
  if (v < 0 || v > 0xffffffff) throw const SsbCryptoException('integer out of range');
  return Uint8List.fromList(
      [(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
}

/// Strict UTF-8 encoder: throws on an unpaired UTF-16 surrogate instead of
/// silently substituting U+FFFD.
///
/// `dart:convert`'s `utf8.encode` is not injective over the full `String`
/// space: a string holding a lone surrogate (reachable via
/// `String.fromCharCodes`, not just a literal) encodes to the exact same
/// bytes as a string holding a real U+FFFD character at that position. Every
/// domain-separation context in this package (vault id, tier, item id, file
/// id) is built by concatenating `utf8Bytes` output, so a non-injective
/// encoder would let two different ids collide into one AAD/MAC input.
/// Rejecting malformed strings up front makes the encoding injective, so
/// distinct ids can never collide this way.
Uint8List utf8Bytes(String s) {
  for (var i = 0; i < s.length; i++) {
    final unit = s.codeUnitAt(i);
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      final next = i + 1 < s.length ? s.codeUnitAt(i + 1) : 0;
      if (next < 0xDC00 || next > 0xDFFF) {
        throw const SsbCryptoException('invalid string');
      }
      i++; // consumed the matching low surrogate
    } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
      throw const SsbCryptoException('invalid string'); // unpaired low surrogate
    }
  }
  return Uint8List.fromList(utf8.encode(s));
}

/// Strict hex decoder: whitespace is ignored, everything else must be an
/// even number of `[0-9a-fA-F]` digits (no sign, no `0x`, no other radix
/// leniency such as `int.parse` has).
Uint8List hexDecode(String hex) {
  final h = hex.replaceAll(RegExp(r'\s'), '');
  if (h.length.isOdd) throw const FormatException('odd hex length');
  int nib(int c) {
    if (c >= 0x30 && c <= 0x39) return c - 0x30;
    if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
    if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
    throw const FormatException('invalid hex digit');
  }

  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = (nib(h.codeUnitAt(2 * i)) << 4) | nib(h.codeUnitAt(2 * i + 1));
  }
  return out;
}

/// Unambiguous field encoding for domain-separation strings: a 4-byte
/// big-endian length followed by the UTF-8 bytes. Concatenating several of
/// these cannot be re-split differently, whatever characters the fields hold.
Uint8List lengthPrefixed(String field) {
  final b = utf8Bytes(field);
  return concatBytes([u32be(b.length), b]);
}

String hexEncode(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Format-v2 domain-separation context (SSB-2026-002, design D8):
///
///     'ssb/v2/' || lp(what) || field_1 || ... || field_n
///
/// where a [String] field is encoded as [lengthPrefixed] and a byte field
/// (`List<int>`, e.g. a `Uint8List`) is appended raw. Raw fields MUST be
/// fixed-width -- integers go through an explicit width helper
/// (`u16be(epoch)`, `u32be(seq)`) and hashes are their fixed digest length --
/// so the encoding is injective: no two field lists produce the same bytes.
/// A bare [int] is refused ([ArgumentError]) precisely so the width is always
/// spelled out at the call site.
Uint8List ctx2(String what, List<Object> fields) {
  final parts = <List<int>>[utf8Bytes('ssb/v2/'), lengthPrefixed(what)];
  for (final f in fields) {
    if (f is String) {
      parts.add(lengthPrefixed(f));
    } else if (f is List<int>) {
      parts.add(f);
    } else {
      throw ArgumentError.value(f, 'fields',
          'ctx2 fields must be String or bytes (use u16be/u32be for integers)');
    }
  }
  return concatBytes(parts);
}

/// SHA-256 of [data] (32 bytes), synchronous. Used for the manifest's
/// item-set hash, slot hashes and the tier-export chain -- public values,
/// never key material.
Uint8List sha256Of(List<int> data) =>
    SHA256Digest().process(data is Uint8List ? data : Uint8List.fromList(data));

/// SHAKE256 XOF. (pointycastle 4.0.0's SHAKEDigest.doFinal passes the wrong
/// offset; doFinalRange is the correct entry point.)
Uint8List shake256(Uint8List input, int outputLength) {
  final d = SHAKEDigest(256)..update(input, 0, input.length);
  final out = Uint8List(outputLength);
  d.doFinalRange(out, 0, outputLength);
  return out;
}
