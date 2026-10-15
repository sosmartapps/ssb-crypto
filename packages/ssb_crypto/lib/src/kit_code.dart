import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// Human-transcribable codes for printed kits (Secret Key, Recovery Key,
/// Beneficiary Kit share S1, attorney share S3).
///
/// Crockford base32 (no I, L, O, U; forgiving on decode), with a 4-byte
/// SHA-256 checksum bound to a label so a code for one purpose is rejected
/// for another, and typos or QR misreads are caught before any crypto runs.
///
/// Format: <LABEL>-XXXXX-XXXXX-...
abstract final class KitCode {
  static const _alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  static Future<String> encode(String label, Uint8List payload) async {
    // Snapshot before the first await (see Aead.seal), so the checksum and
    // the printed digits always describe the same bytes.
    final p = Uint8List.fromList(payload);
    final Uint8List check;
    try {
      check = await _checksum(label, p);
    } catch (_) {
      wipe(p);
      rethrow;
    }
    final joined = concatBytes([p, check]);
    wipe(p);
    final b32 = _toBase32(joined);
    wipe(joined);
    final groups = <String>[];
    for (var i = 0; i < b32.length; i += 5) {
      groups.add(b32.substring(i, i + 5 > b32.length ? b32.length : i + 5));
    }
    return '$label-${groups.join('-')}';
  }

  static Future<Uint8List> decode(String label, String code,
      {required int payloadLength}) async {
    var s = code.toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
    final l = label.toUpperCase().replaceAll('-', '');
    if (!s.startsWith(l)) throw const SsbCryptoException('invalid code');
    s = s.substring(l.length).replaceAll('I', '1').replaceAll('L', '1').replaceAll('O', '0');
    final raw = _fromBase32(s, payloadLength + 4);
    final payload = Uint8List.sublistView(raw, 0, payloadLength);
    final check = Uint8List.sublistView(raw, payloadLength);
    if (!constantTimeEquals(check, await _checksum(label, payload))) {
      throw const SsbCryptoException('invalid code');
    }
    return Uint8List.fromList(payload);
  }

  static Future<Uint8List> _checksum(String label, List<int> payload) async {
    final h = await Sha256().hash(concatBytes([utf8Bytes('ssb/v1/kit|$label|'), payload]));
    return Uint8List.fromList(h.bytes.sublist(0, 4));
  }

  static String _toBase32(Uint8List data) {
    final sb = StringBuffer();
    var buffer = 0, bits = 0;
    for (final b in data) {
      buffer = (buffer << 8) | b;
      bits += 8;
      while (bits >= 5) {
        sb.write(_alphabet[(buffer >> (bits - 5)) & 31]);
        bits -= 5;
      }
      buffer &= (1 << bits) - 1;
    }
    if (bits > 0) sb.write(_alphabet[(buffer << (5 - bits)) & 31]);
    return sb.toString();
  }

  static Uint8List _fromBase32(String s, int expectedLength) {
    if (s.length != (expectedLength * 8 + 4) ~/ 5) {
      throw const SsbCryptoException('invalid code');
    }
    final out = <int>[];
    var buffer = 0, bits = 0;
    for (final ch in s.split('')) {
      final v = _alphabet.indexOf(ch);
      if (v < 0) throw const SsbCryptoException('invalid code');
      buffer = (buffer << 5) | v;
      bits += 5;
      if (bits >= 8) {
        out.add((buffer >> (bits - 8)) & 0xff);
        bits -= 8;
        buffer &= (1 << bits) - 1;
      }
    }
    if (out.length != expectedLength || buffer != 0) {
      throw const SsbCryptoException('invalid code');
    }
    return Uint8List.fromList(out);
  }
}
