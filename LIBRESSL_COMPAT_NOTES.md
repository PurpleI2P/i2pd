# i2pd vs LibreSSL 4.3.2 compatibility notes

Scope: build/test of i2pd against Homebrew LibreSSL 4.3.2 only (no global relink).

## Compatibility matrix

| OpenSSL API/feature | Where i2pd uses it | LibreSSL 4.3.2 | Replacement / shim | Decision in this patchset | Evidence |
|---|---|---|---|---|---|
| OpenSSL 3 provider/keymgmt (`OSSL_PARAM`, `OSSL_PARAM_BLD_*`, `EVP_PKEY_fromdata*`, `EVP_PKEY_CTX_new_from_name`, `EVP_SIGNATURE_fetch`, `EVP_PKEY_sign_message_init`, `EVP_PKEY_verify_message_init`) | `libi2pd/Crypto.cpp`, `libi2pd/Signature.cpp` | **Not available** | None in LibreSSL 4.3.2 | Keep these paths OpenSSL-only (`OPENSSL_PQ` excludes LibreSSL) | Homebrew LibreSSL headers/symbol checks; unresolved refs when OpenSSL 3 headers leaked into build; LibreSSL headers define `OPENSSL_VERSION_NUMBER=0x20000000L`, `LIBRESSL_VERSION_NUMBER=0x4030200fL` |
| OpenSSL 3 KEM via EVP (`EVP_PKEY_Q_keygen`, `EVP_PKEY_encapsulate*`, `EVP_PKEY_decapsulate*`, `EVP_PKEY_get_octet_string_param`) | `libi2pd/PostQuantum.cpp` (original OpenSSL path) | **Not available** | LibreSSL native ML-KEM API | Split ML-KEM from provider PQ: OpenSSL path kept for OpenSSL 3.5+, LibreSSL gets native backend | `libi2pd/PostQuantum.cpp`, `libi2pd/PostQuantum.h`, `libi2pd/Crypto.h` |
| Native ML-KEM (`<openssl/mlkem.h>`, `MLKEM_*`) | `libi2pd/PostQuantum.cpp` (new LibreSSL path) | **Available** (rank 3/4 only) | Direct use | Implemented native backend for LibreSSL; no fake provider emulation | `nm -D libcrypto.so.57 | grep MLKEM_`; runtime probe: `rank=2 unsupported`, `rank=3/4 supported` |
| ML-KEM-512 | i2pd ML-KEM key type handling | **Unavailable** in LibreSSL 4.3.2 native API | None | Disabled under LibreSSL (no rank 2) while keeping 768/1024 | local probe using `MLKEM_private_key_new(rank)` |
| EVP/HMAC/HKDF classic APIs (`EVP_Digest*`, `HMAC*`, `RAND_bytes`, AES-GCM, ChaCha20-Poly1305, SHA) | `libi2pd/Crypto.cpp`, transport/session code | **Available** | Direct use | Kept as-is | Successful full build+link+run against LibreSSL 4.3.2 |
| TLS APIs (`SSL_CTX`, `SSL*`, Boost.Asio SSL integration) | daemon + transport code (`NTCP2`, control HTTPS) | **Available** | Direct use | Kept as-is | `ldd i2pd` resolves `libssl.so.60` and `libcrypto.so.57` from Homebrew LibreSSL |
| X25519/X448/EC/EdDSA core | `libi2pd/Signature.cpp`, `libi2pd/Ed25519.cpp`, identity/transport code | Partially modernized vs OpenSSL 3-only APIs | Existing non-provider codepaths | Kept OpenSSL-3-only APIs guarded; LibreSSL-compatible paths retained | source guards and successful LibreSSL build |
| PQ key selection in LeaseSet/destination parsing | `libi2pd/LeaseSet.cpp`, `libi2pd/Destination.cpp` | **Can support ML-KEM under LibreSSL** | Guard by ML-KEM feature (not provider PQ) | Updated filters to use `OPENSSL_MLKEM` so LibreSSL accepts ML-KEM key types where available | source patch in this branch + successful rebuild/tests |
| Ed25519ph (`SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph`) | `libi2pd/Signature.{h,cpp}`, `libi2pd/Identity.cpp` | Not usable via LibreSSL EVP provider API | `libsodium` Ed25519ph state API | Added optional fallback backend (`USE_LIBSODIUM_ED25519PH`) and wired identity signer/verifier/keygen for type 8 | `test-eddsa-ph` and `test-identity-eddsa-ph` pass in LibreSSL build; `ldd` shows `libsodium.so` |
| ML-DSA-44 (`MLDSA44*` classes) | `libi2pd/Signature.{h,cpp}` | Not available via LibreSSL provider API | `liboqs` ML-DSA-44 API | Added optional fallback backend (`USE_LIBOQS_MLDSA`) with keygen/sign/verify | `test-mldsa44` passes with local `liboqs` |

## Build-system note discovered

When using `clang`, include ordering could pull OpenSSL 3 headers from Homebrew generic include directories before LibreSSL headers, causing OpenSSL-3-only symbols to be compiled and then fail at link-time with LibreSSL.

Patch applied:

- `build/CMakeLists.txt`: prioritize `${OPENSSL_INCLUDE_DIR}` before `${Boost_INCLUDE_DIRS}` in system include ordering.

## Toolchain note: clang + libc++ on Linuxbrew

`clang + libc++` against the default Homebrew Boost binaries fails by C++ ABI mismatch (`std::__1` vs `std::__cxx11`) in `boost_program_options`.

Working approach used here (local-only, no global replacement):

1. Build a local Boost (required libs only: atomic/container/filesystem/program_options) with `clang` and `-stdlib=libc++`.
2. Configure i2pd CMake to resolve Boost from that local prefix (`/tmp/boost-libcxx`) while still resolving LibreSSL from `$(brew --prefix libressl)`.
3. Ensure runpath prefers `/tmp/boost-libcxx/lib` before the global Linuxbrew lib dir.

## Additional API probes (LibreSSL 4.3.2)

- `NID_Ed25519ph` OID exists in headers, but practical EVP key usage is not exposed:
  - `EVP_PKEY_new_raw_private_key(NID_Ed25519ph, ...)` fails.
  - `EVP_PKEY_set_type(..., NID_Ed25519ph)` on raw Ed25519 keys fails.
- No ML-DSA/provider message-sign APIs were found in LibreSSL headers (`EVP_SIGNATURE_fetch`, `EVP_PKEY_sign_message_init`, `EVP_PKEY_verify_message_init`, `OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING`).

Conclusion: ED25519ph/ML-DSA provider-style paths cannot be safely enabled on LibreSSL 4.3.2 directly. To close that gap, this branch introduces optional external backends (`libsodium`/`liboqs`) behind compile-time flags.

## Optional dependency backends added

1. `WITH_LIBSODIUM_ED25519PH` (default ON): enables `USE_LIBSODIUM_ED25519PH` and provides Ed25519ph signer/verifier/keygen on LibreSSL.
2. `WITH_LIBOQS_MLDSA` (default ON): enables `USE_LIBOQS_MLDSA` and provides ML-DSA-44 keygen/sign/verify when OpenSSL provider APIs are unavailable.

Note on `liboqs`: Homebrew `liboqs` links against OpenSSL-3-specific symbols that are incompatible with LibreSSL. For LibreSSL builds, a local `liboqs` built with `-DOQS_USE_OPENSSL=OFF` was used successfully.

## Current verification snapshot

- Build directory: `/tmp/i2pd-libressl-final`
- Compiler: clang/clang++
- Tests: `ctest` => **16/16 passed**
- Runtime check: `i2pd --version` reports `LibreSSL 4.3.2`
- Link check: `ldd i2pd` resolves `libssl.so.60` + `libcrypto.so.57` from Homebrew LibreSSL, plus optional fallback libs (`libsodium`, local `liboqs`)

## What was implemented for ML-KEM

1. Introduced `OPENSSL_MLKEM` feature macro in `libi2pd/Crypto.h`.
2. Kept provider-centric PQ (`OPENSSL_PQ`) OpenSSL-only and explicitly excluded LibreSSL.
3. Reworked `libi2pd/PostQuantum.{h,cpp}` to support:
   - OpenSSL 3.5+ EVP/provider backend.
   - LibreSSL native ML-KEM backend (`MLKEM_generate_key`, `MLKEM_encap`, `MLKEM_decap`, key parse/new/free).
4. Updated transport/config identity call-sites to gate ML-KEM behavior on `OPENSSL_MLKEM` (not provider PQ).

## External references used

- LibreSSL 4.3.2 release/docs/changelog: https://www.libressl.org/releases.html
- LibreSSL source headers (`opensslv.h`, `mlkem.h`) in Homebrew prefix:
  - `$(brew --prefix libressl)/include/openssl/opensslv.h`
  - `$(brew --prefix libressl)/include/openssl/mlkem.h`
- OpenSSL provider API docs (for unsupported APIs under LibreSSL):
  - https://www.openssl.org/docs/man3.0/man3/OSSL_PARAM.html
  - https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_fromdata.html
  - https://www.openssl.org/docs/man3.0/man3/EVP_SIGNATURE_fetch.html
