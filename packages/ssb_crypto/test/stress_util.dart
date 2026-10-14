// Shared helpers for the stress_*_test.dart adversarial suites (not a test).
import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

/// Fixed-seed PRNG so every failure reproduces.
Random seeded(int n) => Random(0x55B000 + n);

Uint8List rnd(Random r, int n) =>
    Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));

Uint8List flip(Uint8List b, int i, [int mask = 0x01]) {
  final c = Uint8List.fromList(b);
  c[i] ^= mask;
  return c;
}

/// null  => threw SsbCryptoException (the clean, typed failure we want)
/// else  => description of what went wrong (accepted / wrong error type).
Future<String?> outcome(FutureOr<dynamic> Function() f) async {
  try {
    await f();
    return 'ACCEPTED';
  } on SsbCryptoException {
    return null;
  } catch (e) {
    return 'WRONG-ERROR ${e.runtimeType}: ${e.toString().split('\n').first}';
  }
}

/// Collects failures across thousands of checks so one report lists them.
class Fails {
  final List<String> _l = [];
  int checks = 0;
  void add(String s) => _l.add(s);

  Future<void> mustFail(String label, FutureOr<dynamic> Function() f) async {
    checks++;
    final o = await outcome(f);
    if (o != null) _l.add('$label -> $o');
  }

  void check(bool ok, String label) {
    checks++;
    if (!ok) _l.add(label);
  }

  void done() {
    if (_l.isNotEmpty) {
      fail('${_l.length}/$checks checks failed; first: ${_l.take(8).join(' | ')}');
    }
  }
}
