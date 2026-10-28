/// Format-v1 read paths for the v1 -> v2 migration ONLY (SSB-2026-002).
///
/// Deliberately not exported from `ssb_crypto.dart`: importing this library
/// is an explicit statement that the code is reading pre-Phase-1 objects in
/// order to re-seal them. See `src/legacy_v1.dart`.
library;

export 'src/legacy_v1.dart';
