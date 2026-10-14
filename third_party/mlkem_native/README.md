# mlkem_native

A Flutter FFI plugin that provides native ML-KEM (Module Lattice-based Key Encapsulation Mechanism) cryptographic operations. This plugin wraps the [mlkem-native](https://github.com/pq-code-package/mlkem-native) library to provide high-performance post-quantum cryptography for Flutter applications.

## Features

- **Post-Quantum Security**: Implements ML-KEM, a quantum-resistant key encapsulation mechanism based on FIPS 203
- **Multiple Security Levels**: Support for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- **High Performance**: Native C/Assembly implementation for optimal performance
- **Cross-Platform**: Works on Android, iOS, macOS, Linux, and Windows
- **Type Safety**: Full Dart type safety with proper error handling
- **Zero Dependencies**: No external cryptographic dependencies required

## Supported Platforms

- ✅ Android (ARM64, x86_64)
- ✅ iOS (ARM64, x86_64)
- ✅ macOS (ARM64, x86_64)
- ✅ Linux (x86_64, ARM64)
- ✅ Windows (x86_64)

## Security Levels

| Security Level | Public Key | Secret Key | Ciphertext | Shared Secret | Security Level |
|----------------|------------|------------|------------|---------------|----------------|
| ML-KEM-512     | 800 bytes  | 1632 bytes | 768 bytes  | 32 bytes      | Level 1        |
| ML-KEM-768     | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes      | Level 3        |
| ML-KEM-1024    | 1472 bytes | 3168 bytes | 1440 bytes | 32 bytes      | Level 5        |

## Quick Start

### Installation

Add `mlkem_native` to your `pubspec.yaml`:

```yaml
dependencies:
  mlkem_native: ^1.0.1
```

### Basic Usage

```dart
import 'package:mlkem_native/mlkem768.dart';

void main() {
  // Create an instance for ML-KEM-768 (recommended for most applications)
  final mlkem = MLKEM768();
  
  // Generate a key pair
  final keyPair = mlkem.generateKeyPair();
  
  // Encapsulate a shared secret using the public key
  final result = mlkem.encapsulate(keyPair.publicKey);
  
  // Decapsulate the shared secret using the secret key
  final sharedSecret = mlkem.decapsulate(result.ciphertext, keyPair.secretKey);
  
  print('Shared secret: ${sharedSecret.length} bytes');
}
```

### Advanced Usage

```dart
import 'package:mlkem_native/mlkem768.dart';
import 'package:mlkem_native/mlkem512.dart';
import 'package:mlkem_native/mlkem1024.dart';

void main() {
  // Choose your security level
  final mlkem512 = MLKEM512();   // Level 1 security
  final mlkem768 = MLKEM768();   // Level 3 security (recommended)
  final mlkem1024 = MLKEM1024(); // Level 5 security
  
  // Generate key pair
  final keyPair = mlkem768.generateKeyPair();
  
  // Encapsulate with error handling
  try {
    final result = mlkem768.encapsulate(keyPair.publicKey);
    print('Ciphertext: ${result.ciphertext.length} bytes');
    print('Shared secret: ${result.sharedSecret.length} bytes');
  } on MLKEMEncapsulationFailedException catch (e) {
    print('Encapsulation failed: ${e.cError}');
  }
  
  // Decapsulate with error handling
  try {
    final sharedSecret = mlkem768.decapsulate(result.ciphertext, keyPair.secretKey);
    print('Decapsulation successful: ${sharedSecret.length} bytes');
  } on MLKEMDecapsulationFailedException catch (e) {
    print('Decapsulation failed: ${e.cError}');
  }
}
```

## API Reference

### Classes

#### `MLKEM512`, `MLKEM768`, `MLKEM1024`

Main classes for ML-KEM operations at different security levels.

**Methods:**
- `KeyPair generateKeyPair({Uint8List? coins})` - Generates a new key pair
- `EncapsulationResult encapsulate(Uint8List publicKey, {Uint8List? coins})` - Encapsulates a shared secret
- `Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey)` - Decapsulates a shared secret

#### `KeyPair`

Represents a public/secret key pair.

**Properties:**
- `Uint8List publicKey` - The public key
- `Uint8List secretKey` - The secret key

#### `EncapsulationResult`

Result of an encapsulation operation.

**Properties:**
- `Uint8List ciphertext` - The ciphertext
- `Uint8List sharedSecret` - The generated shared secret

### Exceptions

- `MLKEMKeyPairGenerationException` - Key pair generation failed
- `MLKEMPublicKeyWrongLengthException` - Public key has wrong length
- `MLKEMSecretKeyWrongLengthException` - Secret key has wrong length
- `MLKEMCiphertextWrongLengthException` - Ciphertext has wrong length
- `MLKEMEncapsulationFailedException` - Encapsulation operation failed
- `MLKEMDecapsulationFailedException` - Decapsulation operation failed

## License

This project is licensed under the same license as mlkem-native. See [LICENSE](LICENSE) for details.

## Links

- [mlkem-native Repository](https://github.com/pq-code-package/mlkem-native)
- [ML-KEM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Flutter FFI Documentation](https://docs.flutter.dev/development/platform-integration/c-interop)

## Support

For issues and questions:
- [GitHub Issues](https://github.com/rkz-app/flutter_mlkem_native/issues)
