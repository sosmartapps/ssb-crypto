import 'dart:convert';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Matcher get throwsSsb => throwsA(isA<SsbCryptoException>());

void main() {
  group('utf8Bytes injectivity', () {
    test('well-formed strings still encode exactly like dart:convert', () {
      for (final s in ['', 'plain', 'vault-123', 'emoji: 🎉', 'ssb/v1/ik|vault:V|tier:ice|item:X']) {
        expect(utf8Bytes(s), utf8.encode(s));
      }
    });

    test('a lone high surrogate is rejected, not silently replaced', () {
      final loneHigh = String.fromCharCodes([0xD800]);
      expect(() => utf8Bytes(loneHigh), throwsSsb);
    });

    test('a lone low surrogate is rejected', () {
      final loneLow = String.fromCharCodes([0xDC00]);
      expect(() => utf8Bytes(loneLow), throwsSsb);
    });

    test('a valid surrogate pair still encodes fine', () {
      final pair = String.fromCharCodes([0xD83D, 0xDE00]); // 😀
      expect(utf8Bytes(pair), utf8.encode(pair));
    });

    test(
        'regression: a lone surrogate used to collide with the literal U+FFFD '
        'replacement character at the same position (dart:convert utf8.encode '
        'maps both to the same bytes) -- that collision is now refused rather '
        'than silently accepted, so two distinct ids can never produce the '
        'same domain-separation context', () {
      final idWithLoneSurrogate = 'abc${String.fromCharCodes([
            0xD800
          ])}def';
      final idWithReplacementChar = 'abc\u{FFFD}def';

      // Precondition: dart:convert itself still collapses these to one
      // byte sequence -- this is the bug this test guards against.
      expect(utf8.encode(idWithLoneSurrogate), utf8.encode(idWithReplacementChar));

      // Fix: utf8Bytes refuses the malformed one instead of returning the
      // same bytes as the well-formed one.
      expect(() => utf8Bytes(idWithLoneSurrogate), throwsSsb);
      expect(utf8Bytes(idWithReplacementChar), utf8.encode(idWithReplacementChar));
    });
  });
}
