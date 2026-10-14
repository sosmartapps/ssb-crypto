import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    // SSB PATCH: web targets request no code assets, and touching
    // `input.config.code` there throws and fails the whole build. The web
    // survivor portal uses the pure-Dart PQ backend instead (see
    // packages/ssb_crypto/lib/src/pq/pq.dart).
    if (!input.config.buildCodeAssets) return;

    final targetOS = input.config.code.targetOS;
    final arch = input.config.code.targetArchitecture;

    final levels = [44, 65, 87];

    for (final level in levels) {
      final cBuilder = CBuilder.library(
        name: 'mldsa${level}_native',
        assetName: 'src/mldsa${level}_bindings.dart',
        sources: [
          'src/mldsa-native/mldsa/mldsa_native.c',
          'src/mldsa-native/mldsa/mldsa_native_asm.S',
          'src/os_rng.c',
        ],
        // Include directories (equivalent to target_include_directories)
        includes: [
          'src/include',
          'src', // For multilevel_config.h and potentially other local includes
          'src/mldsa-native/mldsa', // MLK_INCLUDE_DIR from your CMake
          'src/mldsa-native/mldsa/src',
          'src/mldsa-native', // ${CMAKE_CURRENT_LIST_DIR}/mlkem-native
        ],

        flags: [
          '-Wall',
          '-Wextra',
          '-Werror',
          '-Wmissing-prototypes',
          '-Wshadow',
          '-Wpointer-arith',
          '-Wno-long-long',
          '-Wno-unknown-pragmas',
          '-Wredundant-decls',
          '-Wno-unused-command-line-argument',
          '-Wno-unused-function',
          '-fomit-frame-pointer',
          '-std=c99',
          '-pedantic',
          if (targetOS == OS.macOS || targetOS == OS.iOS) ...[
            '-framework',
            'Security',
            '-framework',
            'Foundation',
          ],
          if (targetOS == OS.macOS && arch == Architecture.arm64)
            '-DMLD_FORCE_AARCH64',
          if (targetOS == OS.android) '-Wl,-z,max-page-size=16384',
        ],
        // Compiler defines (equivalent to target_compile_definitions)
        defines: {
          'MLD_CONFIG_PARAMETER_SET': '$level',
          'MLD_CONFIG_NAMESPACE_PREFIX': 'mldsa$level',
          // Define DART_SHARED_LIB to ensure proper symbol visibility if needed
          'DART_SHARED_LIB': null,
        },
      );
      await cBuilder.run(
        input: input,
        output: output,
        logger: Logger('')
          ..level = .ALL
          ..onRecord.listen((record) => print(record.message)),
      );
    }
  });
}
