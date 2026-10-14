import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' show calloc;
import 'package:mlkem_native/src/models.dart';

/// SSB PATCH 3: wipe native memory that held secret material before freeing.
void _wipeFree(ffi.Pointer<ffi.Uint8> p, int len) {
  p.asTypedList(len).fillRange(0, len, 0);
  calloc.free(p);
}

class InternalParameters {
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int ciphertextBytes;
  final int sharedBytes;

  final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
  )
  keypairDerand;
  final int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>) keypair;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
  )
  encDerand;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
  )
  enc;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
  )
  dec;

  InternalParameters({
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.ciphertextBytes,
    required this.sharedBytes,
    required this.keypair,
    required this.keypairDerand,
    required this.encDerand,
    required this.enc,
    required this.dec,
  });
}

abstract class MLKEM {
  KeyPair generateKeyPair({Uint8List? coins});
  EncapsulationResult encapsulate(Uint8List publicKey, {Uint8List? coins});
  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey);
}

class MLKEMImpl<T extends InternalParameters> implements MLKEM {
  final T _params;

  /// ML-KEM encapsulation coins: 32 bytes (FIPS 203 m).
  static const randomCoinsSize = 32;

  /// ML-KEM key generation coins: 64 bytes (FIPS 203 d || z).
  /// SSB PATCH 1: upstream wrapper checked keygen coins against 32 bytes,
  /// but crypto_kem_keypair_derand reads 2*MLKEM_SYMBYTES = 64 bytes,
  /// so a 32-byte buffer caused a 32-byte heap over-read.
  static const keypairCoinsSize = 64;

  MLKEMImpl(this._params);

  @override
  KeyPair generateKeyPair({Uint8List? coins}) {
    // SSB PATCH 4: validate before allocating, so a bad argument leaks nothing.
    if (coins != null && coins.length != keypairCoinsSize) {
      throw MLKEMCoinsWrongSize();
    }
    final pk = calloc<ffi.Uint8>(_params.publicKeyBytes);
    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    int result;
    ffi.Pointer<ffi.Uint8>? coinsPtr;
    if (coins != null) {
      coinsPtr = calloc<ffi.Uint8>(keypairCoinsSize);
      coinsPtr.asTypedList(keypairCoinsSize).setAll(0, coins);
      result = _params.keypairDerand(pk, sk, coinsPtr);
    } else {
      result = _params.keypair(pk, sk);
    }

    if (result != 0) {
      calloc.free(pk);
      _wipeFree(sk, _params.secretKeyBytes);
      if (coinsPtr != null) {
        _wipeFree(coinsPtr, keypairCoinsSize);
      }
      throw MLKEMKeyPairGenerationException(result);
    }

    final pkBytes = Uint8List.fromList(pk.asTypedList(_params.publicKeyBytes));
    final skBytes = Uint8List.fromList(sk.asTypedList(_params.secretKeyBytes));

    calloc.free(pk);
    _wipeFree(sk, _params.secretKeyBytes);

    if (coinsPtr != null) {
      _wipeFree(coinsPtr, keypairCoinsSize);
    }

    return KeyPair(secretKey: skBytes, publicKey: pkBytes);
  }

  @override
  EncapsulationResult encapsulate(Uint8List publicKey, {Uint8List? coins}) {
    if (publicKey.length != _params.publicKeyBytes) {
      throw MLKEMPublicKeyWrongLengthException();
    }
    if (coins != null && coins.length != randomCoinsSize) {
      throw MLKEMCoinsWrongSize();
    }

    final pk = calloc<ffi.Uint8>(_params.publicKeyBytes);
    pk.asTypedList(_params.publicKeyBytes).setAll(0, publicKey);

    final ct = calloc<ffi.Uint8>(_params.ciphertextBytes);
    final ss = calloc<ffi.Uint8>(_params.sharedBytes);

    int result;
    ffi.Pointer<ffi.Uint8>? coinsPtr;
    if (coins != null) {
      coinsPtr = calloc<ffi.Uint8>(randomCoinsSize);
      coinsPtr.asTypedList(randomCoinsSize).setAll(0, coins);
      result = _params.encDerand(ct, ss, pk, coinsPtr);
    } else {
      result = _params.enc(ct, ss, pk);
    }

    if (result != 0) {
      calloc.free(pk);
      calloc.free(ct);
      _wipeFree(ss, _params.sharedBytes);
      if (coinsPtr != null) {
        _wipeFree(coinsPtr, randomCoinsSize);
      }
      throw MLKEMEncapsulationFailedException(result);
    }

    final ctBytes = Uint8List.fromList(ct.asTypedList(_params.ciphertextBytes));
    final ssBytes = Uint8List.fromList(ss.asTypedList(_params.sharedBytes));

    calloc.free(pk);
    calloc.free(ct);
    _wipeFree(ss, _params.sharedBytes);

    if (coinsPtr != null) {
      _wipeFree(coinsPtr, randomCoinsSize);
    }

    return EncapsulationResult(ciphertext: ctBytes, sharedSecret: ssBytes);
  }

  @override
  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) {
    if (ciphertext.length != _params.ciphertextBytes) {
      throw MLKEMCiphertextWrongLengthException();
    }
    if (secretKey.length != _params.secretKeyBytes) {
      throw MLKEMSecretKeyWrongLengthException();
    }
    final ct = calloc<ffi.Uint8>(_params.ciphertextBytes);
    ct.asTypedList(_params.ciphertextBytes).setAll(0, ciphertext);

    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    sk.asTypedList(_params.secretKeyBytes).setAll(0, secretKey);

    final ss = calloc<ffi.Uint8>(_params.sharedBytes);

    final result = _params.dec(ss, ct, sk);
    if (result != 0) {
      calloc.free(ct);
      _wipeFree(sk, _params.secretKeyBytes);
      _wipeFree(ss, _params.sharedBytes);
      throw MLKEMDecapsulationFailedException(result);
    }

    final ssBytes = Uint8List.fromList(ss.asTypedList(_params.sharedBytes));

    calloc.free(ct);
    _wipeFree(sk, _params.secretKeyBytes);
    _wipeFree(ss, _params.sharedBytes);

    return ssBytes;
  }
}
