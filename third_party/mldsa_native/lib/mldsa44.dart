import 'package:mldsa_native/src/mldsa44_bindings.dart';
import 'package:mldsa_native/src/models.dart';
import 'package:mldsa_native/src/shared.dart';

class MLDSA44 extends MLDSAImpl<InternalParameters> implements MLDSA {
  MLDSA44._(super._params);

  factory MLDSA44() {
    final params = InternalParameters(
      publicKeyBytes: MLDSA44_PUBLICKEYBYTES,
      secretKeyBytes: MLDSA44_SECRETKEYBYTES,
      keypair: mldsa44_keypair,
      keypairDerand: mldsa44_keypair_internal,
      signatureBytes: MLDSA44_BYTES,
      sign: mldsa44_signature,
      verify: mldsa44_verify,
    );
    return MLDSA44._(params);
  }
}
