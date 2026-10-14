import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' show calloc;
import 'package:mldsa_native/src/models.dart';

/// SSB PATCH: wipe native memory holding secret material before freeing.
void _wipeFree(ffi.Pointer<ffi.Uint8> p, int len) {
  p.asTypedList(len).fillRange(0, len, 0);
  calloc.free(p);
}

/// FIPS 204: the context string is at most 255 bytes.
const _maxContextBytes = 255;

abstract class MLDSA {
  KeyPair generateKeyPair({Uint8List? coins});
  Uint8List sign(
    Uint8List privateKey,
    Uint8List message, {
    Uint8List? context,
    Uint8List? coins,
  });
  bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
  });
}

class MLDSAImpl<T extends InternalParameters> implements MLDSA {
  final T _params;

  static const randomCoinsSize = 32;

  MLDSAImpl(this._params);

  @override
  KeyPair generateKeyPair({Uint8List? coins}) {
    // SSB PATCH 3: validate before allocating anything.
    if (coins != null && coins.length != randomCoinsSize) {
      throw MLDSACoinsWrongSize();
    }
    final pk = calloc<ffi.Uint8>(_params.publicKeyBytes);
    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    int result;
    ffi.Pointer<ffi.Uint8>? coinsPtr;
    if (coins != null) {
      coinsPtr = calloc<ffi.Uint8>(randomCoinsSize);
      coinsPtr.asTypedList(randomCoinsSize).setAll(0, coins);
      result = _params.keypairDerand(pk, sk, coinsPtr);
    } else {
      result = _params.keypair(pk, sk);
    }

    if (result != 0) {
      calloc.free(pk);
      _wipeFree(sk, _params.secretKeyBytes);
      if (coinsPtr != null) {
        _wipeFree(coinsPtr, randomCoinsSize);
      }
      throw MLDSAKeyPairGenerationException(result);
    }

    final pkBytes = Uint8List.fromList(pk.asTypedList(_params.publicKeyBytes));
    final skBytes = Uint8List.fromList(sk.asTypedList(_params.secretKeyBytes));

    calloc.free(pk);
    _wipeFree(sk, _params.secretKeyBytes);

    if (coinsPtr != null) {
      _wipeFree(coinsPtr, randomCoinsSize);
    }

    return KeyPair(secretKey: skBytes, publicKey: pkBytes);
  }

  @override
  Uint8List sign(
    Uint8List privateKey,
    Uint8List message, {
    Uint8List? context,
    Uint8List? coins,
  }) {
    // SSB PATCH 3: the C signer reads exactly secretKeyBytes from `sk`, and the
    // zeroization patch writes exactly that many zeros back, so the buffer
    // MUST be that size. Reject anything else before touching native memory.
    if (privateKey.length != _params.secretKeyBytes) {
      throw MLDSAWrongLengthException('private key',
          expected: _params.secretKeyBytes, actual: privateKey.length);
    }
    if (coins != null && coins.length != randomCoinsSize) {
      throw MLDSACoinsWrongSize();
    }
    _checkContext(context);

    final sig = calloc<ffi.Uint8>(_params.signatureBytes);
    final siglen = calloc<ffi.Size>();
    final m = calloc<ffi.Uint8>(message.length);
    m.asTypedList(message.length).setAll(0, message);
    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    sk.asTypedList(_params.secretKeyBytes).setAll(0, privateKey);

    final ctx = _toNativeBuffer(context);
    try {
      final result = _params.sign(
        sig,
        siglen,
        m,
        message.length,
        ctx,
        context?.length ?? 0,
        sk,
      );
      if (result != 0) {
        throw MLDSAKeyPairGenerationException(result);
      }
      return Uint8List.fromList(sig.asTypedList(_params.signatureBytes));
    } finally {
      calloc.free(sig);
      calloc.free(siglen);
      calloc.free(m);
      _wipeFree(sk, _params.secretKeyBytes);
      _freeNativeBuffer(ctx);
    }
  }

  @override
  bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
  }) {
    // SSB PATCH 3: the C verifier reads exactly publicKeyBytes from `pk`, so a
    // wrong-size key is a caller bug and is refused outright. A wrong-size
    // SIGNATURE is simply not a valid signature (FIPS 204): answer false
    // without calling C.
    if (publicKey.length != _params.publicKeyBytes) {
      throw MLDSAWrongLengthException('public key',
          expected: _params.publicKeyBytes, actual: publicKey.length);
    }
    _checkContext(context);
    if (signature.length != _params.signatureBytes) return false;

    final sig = calloc<ffi.Uint8>(signature.length);
    sig.asTypedList(signature.length).setAll(0, signature);
    final m = calloc<ffi.Uint8>(message.length);
    m.asTypedList(message.length).setAll(0, message);
    final pk = calloc<ffi.Uint8>(publicKey.length);
    pk.asTypedList(publicKey.length).setAll(0, publicKey);

    final ctx = _toNativeBuffer(context);
    try {
      final result = _params.verify(
        sig,
        signature.length,
        m,
        message.length,
        ctx,
        context?.length ?? 0,
        pk,
      );
      return result == 0;
    } finally {
      calloc.free(sig);
      calloc.free(m);
      calloc.free(pk);
      _freeNativeBuffer(ctx);
    }
  }

  static void _checkContext(Uint8List? context) {
    if (context != null && context.length > _maxContextBytes) {
      throw MLDSAWrongLengthException('context',
          expected: _maxContextBytes, actual: context.length);
    }
  }

  static ffi.Pointer<ffi.Uint8> _toNativeBuffer(Uint8List? data) {
    if (data == null || data.isEmpty) {
      return ffi.Pointer.fromAddress(0);
    }
    final ptr = calloc<ffi.Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }

  static void _freeNativeBuffer(ffi.Pointer<ffi.Uint8> ptr) {
    if (ptr.address != 0) {
      calloc.free(ptr);
    }
  }
}
