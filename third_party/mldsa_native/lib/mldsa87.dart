import 'package:mldsa_native/src/mldsa87_bindings.dart';
import 'package:mldsa_native/src/models.dart';
import 'package:mldsa_native/src/shared.dart';

class MLDSA87 extends MLDSAImpl<InternalParameters> implements MLDSA {
  MLDSA87._(super._params);

  factory MLDSA87() {
    final params = InternalParameters(
      publicKeyBytes: MLDSA87_PUBLICKEYBYTES,
      secretKeyBytes: MLDSA87_SECRETKEYBYTES,
      keypair: mldsa87_keypair,
      keypairDerand: mldsa87_keypair_internal,
      signatureBytes: MLDSA87_BYTES,
      sign: mldsa87_signature,
      verify: mldsa87_verify,
    );
    return MLDSA87._(params);
  }
}
