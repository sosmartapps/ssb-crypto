library;

// Post-quantum primitives, picked per platform at compile time.
//
// Mobile and desktop use the vendored C implementations (PQ Code Package)
// through FFI. The web survivor portal has no FFI, so it uses the pure-Dart
// `pqcrypto` implementation. Both are exercised against each other in
// `test/pq_backend_test.dart`, and X-Wing's official vectors run on both.
export 'pq_native.dart' if (dart.library.js_interop) 'pq_web.dart';
