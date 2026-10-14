import 'package:mlkem_native/src/mlkem_1024_bindings.dart';
import 'package:mlkem_native/src/shared.dart';
export 'package:mlkem_native/src/models.dart';

class MLKEM1024 extends MLKEMImpl<InternalParameters> {
  MLKEM1024._(super._params);

  factory MLKEM1024() {
    final params = InternalParameters(
      publicKeyBytes: MLKEM1024_PUBLICKEYBYTES,
      secretKeyBytes: MLKEM1024_SECRETKEYBYTES,
      ciphertextBytes: MLKEM1024_CIPHERTEXTBYTES,
      sharedBytes: MLKEM1024_SYMBYTES,
      keypair: mlkem1024_keypair,
      keypairDerand: mlkem1024_keypair_derand,
      encDerand: mlkem1024_enc_derand,
      enc: mlkem1024_enc,
      dec: mlkem1024_dec,
    );
    return MLKEM1024._(params);
  }
}
