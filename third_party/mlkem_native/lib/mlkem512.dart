import 'package:mlkem_native/src/mlkem512_bindings.dart';
import 'package:mlkem_native/src/shared.dart';

export 'package:mlkem_native/src/models.dart';

class MLKEM512 extends MLKEMImpl<InternalParameters> implements MLKEM {
  MLKEM512._(super._params);

  factory MLKEM512() {
    final params = InternalParameters(
      publicKeyBytes: MLKEM512_PUBLICKEYBYTES,
      secretKeyBytes: MLKEM512_SECRETKEYBYTES,
      ciphertextBytes: MLKEM512_CIPHERTEXTBYTES,
      sharedBytes: MLKEM512_SYMBYTES,
      keypair: mlkem512_keypair,
      keypairDerand: mlkem512_keypair_derand,
      encDerand: mlkem512_enc_derand,
      enc: mlkem512_enc,
      dec: mlkem512_dec,
    );
    return MLKEM512._(params);
  }
}
