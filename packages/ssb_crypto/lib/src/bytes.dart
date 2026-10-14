import 'dart:convert';
import 'package:pointycastle/digests/shake.dart';
import 'dart:math';
import 'dart:typed_data';

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

Uint8List u16be(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);

Uint8List u32be(int v) => Uint8List.fromList(
    [(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);

Uint8List utf8Bytes(String s) => Uint8List.fromList(utf8.encode(s));

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

/// SHAKE256 XOF. (pointycastle 4.0.0's SHAKEDigest.doFinal passes the wrong
/// offset; doFinalRange is the correct entry point.)
Uint8List shake256(Uint8List input, int outputLength) {
  final d = SHAKEDigest(256)..update(input, 0, input.length);
  final out = Uint8List(outputLength);
  d.doFinalRange(out, 0, outputLength);
  return out;
}
