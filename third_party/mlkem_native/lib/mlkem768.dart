import 'package:mlkem_native/src/mlkem768_bindings.dart';
import 'package:mlkem_native/src/shared.dart';

export 'package:mlkem_native/src/models.dart';

class MLKEM768 extends MLKEMImpl<InternalParameters> implements MLKEM {
  MLKEM768._(super._params);
  factory MLKEM768() {
    final params = InternalParameters(
      publicKeyBytes: MLKEM768_PUBLICKEYBYTES,
      secretKeyBytes: MLKEM768_SECRETKEYBYTES,
      ciphertextBytes: MLKEM768_CIPHERTEXTBYTES,
      sharedBytes: MLKEM768_SYMBYTES,
      keypair: mlkem768_keypair,
      keypairDerand: mlkem768_keypair_derand,
      encDerand: mlkem768_enc_derand,
      enc: mlkem768_enc,
      dec: mlkem768_dec,
    );
    return MLKEM768._(params);
  }
}
