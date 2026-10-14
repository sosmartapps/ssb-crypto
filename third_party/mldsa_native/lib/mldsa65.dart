import 'package:mldsa_native/src/mldsa65_bindings.dart';
import 'package:mldsa_native/src/models.dart';
import 'package:mldsa_native/src/shared.dart';

class MLDSA65 extends MLDSAImpl<InternalParameters> implements MLDSA {
  MLDSA65._(super._params);

  factory MLDSA65() {
    final params = InternalParameters(
      publicKeyBytes: MLDSA65_PUBLICKEYBYTES,
      secretKeyBytes: MLDSA65_SECRETKEYBYTES,
      keypair: mldsa65_keypair,
      keypairDerand: mldsa65_keypair_internal,
      signatureBytes: MLDSA65_BYTES,
      sign: mldsa65_signature,
      verify: mldsa65_verify,
    );
    return MLDSA65._(params);
  }
}
