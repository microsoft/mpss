# MPSS – A Multi-Platform Secure Signing Library

Modern operating systems provide various methods for safeguarding private cryptographic keys through hardware.
MPSS is a multi-platform C++ library for generating and storing (secret) digital signature keys.
It offers a unified API so that downstream applications do not need to worry about the specific APIs used by different operating systems.

In addition to the core library, MPSS includes an OpenSSL 3.x provider, which enables MPSS to be used easily through the OpenSSL API.

MPSS uses the following technologies on the different supported platforms:

| Platform | API |
|----------|-----|
| Windows | [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) if available; TPM-backed [MS_PLATFORM_CRYPTO_PROVIDER](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider) otherwise |
| macOS / iOS | [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave) if available; [Keychain](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain) otherwise |
| Android | [StrongBox](https://developer.android.com/privacy-and-security/keystore) if available; [Trusted Execution Environment](https://source.android.com/docs/security/features/trusty) otherwise |

## Compiling for different platforms

MPSS API depends on [Microsoft GSL](https://GitHub.com/Microsoft/GSL) and the library uses [GoogleTest](https://GitHub.com/Google/GoogleTest) for testing.
The OpenSSL provider naturally requires [OpenSSL](https://GitHub.com/openssl/openssl).
MPSS provides the relevant dependencies file ([vcpkg.json](vcpkg.json)) for [vcpkg](https://GitHub.com/Microsoft/vcpkg).

### Windows

When configuring with CMake, simply provide the path to the `vcpkg` toolchain file, as follows:

```cmd
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
```

### macOS

As for Windows, when configuring with CMake, you only need to provide the path to the `vcpkg` toolchain file:

```bash
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
```

### iOS

To build mpss for iOS and iOS simulator (arm64 in this example), take the following steps:
```bash
# Configure for separate build directories.
cmake -S . -B build-ios-device -GXcode                                      \
    -DCMAKE_SYSTEM_NAME=iOS                                                 \
    -DCMAKE_OSX_SYSROOT=iphoneos                                            \
    -DCMAKE_OSX_ARCHITECTURES=arm64                                         \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"   \
    -DMPSS_BUILD_MPSS_CORE_STATIC=ON                                        \
    -DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON # only if building also mpss-openssl
cmake -S . -B build-ios-simulator -GXcode                                   \
    -DCMAKE_SYSTEM_NAME=iOS                                                 \
    -DCMAKE_OSX_SYSROOT=iphonesimulator                                     \
    -DCMAKE_OSX_ARCHITECTURES=arm64                                         \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"   \
    -DMPSS_BUILD_MPSS_CORE_STATIC=ON                                        \
    -DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON # only if building also mpss-openssl

# Build and install to local directories.
cmake --build build-ios-device --config Release -j
cmake --build build-ios-simulator --config Release -j
cmake --install build-ios-device --config Release --prefix install-ios-device
cmake --install build-ios-simulator --config Release --prefix install-ios-simulator

# We need some temporary directory structure to create xcframeworks
mkdir -p xcf/include/mpss/{device,simulator}
rsync -a install-ios-device/include/mpss-0.2/mpss xcf/include/mpss/device/mpss
rsync -a install-ios-simulator/include/mpss-0.2/mpss xcf/include/mpss/simulator/mpss
rsync -a build-ios-device/vcpkg_installed/arm64-ios/include/gsl xcf/include/mpss/device
rsync -a build-ios-simulator/vcpkg_installed/arm64-ios/include/gsl xcf/include/mpss/simulator

# Only if building also mpss-openssl.
mkdir -p xcf/include/mpss-openssl/{device,simulator}
rsync -a install-ios-device/include/mpss-0.2/mpss-openssl xcf/include/mpss-openssl/device/mpss-openssl
rsync -a install-ios-simulator/include/mpss-0.2/mpss-openssl xcf/include/mpss-openssl/simulator/mpss-openssl
rsync -a build-ios-device/vcpkg_installed/arm64-ios/include/openssl xcf/include/mpss-openssl/device
rsync -a build-ios-simulator/vcpkg_installed/arm64-ios/include/openssl xcf/include/mpss-openssl/simulator

# Create an XCFramework for mpss.
xcodebuild -create-xcframework                                      \
    -library install-ios-device/lib/mpss-0.2/libmpss_static.a       \
    -headers xcf/include/mpss/device                                \
    -library install-ios-simulator/lib/mpss-0.2/libmpss_static.a    \
    -headers xcf/include/mpss/simulator                             \
    -output libmpss-0.2.xcframework

# Only if building also mpss-openssl.
xcodebuild -create-xcframework                                          \
    -library install-device/lib/mpss-0.2/libmpss_openssl_static.a       \
    -headers xcf/include/mpss-openssl/device                            \
    -library install-simulator/lib/mpss-0.2/libmpss_openssl_static.a    \
    -headers xcf/include/mpss-openssl/simulator                         \
    -output libmpss_openssl-0.2.xcframework
```
One you have the XCFramework(s), you can simply include them in your Xcode project as Framework dependencies.
You will naturally still need to build OpenSSL itself for iOS to be able to load and use the OpenSSL provider.

### Android
Generate Ninja build files for cross-compiling to the x64 Android simulator.
The vcpkg toolchain file is specified to satisfy build dependencies of MPSS.

```cmd
cmake -S . -B buildX64                                                      ^
  -GNinja                                                                   ^
  -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"    ^
  -DVCPKG_TARGET_TRIPLET=x64-android                                        ^
  -DCMAKE_SYSTEM_NAME=Android                                               ^
  -DCMAKE_SYSTEM_VERSION=%ANDROID_API_VERSION%                              ^
  -DCMAKE_ANDROID_ARCH_ABI=x86_64                                           ^
  -DCMAKE_MAKE_PROGRAM="%NINJA_ROOT%\ninja.exe"                             ^
  -DCMAKE_ANDROID_NDK="%ANDROID_NDK_HOME%"
```

Generate Ninja build files for cross-compiling to arm64.

```cmd
cmake -S . -B buildArm                                                      ^
  -GNinja                                                                   ^
  -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"    ^
  -DVCPKG_TARGET_TRIPLET=arm64-android                                      ^
  -DCMAKE_SYSTEM_NAME=Android                                               ^
  -DCMAKE_SYSTEM_VERSION=%ANDROID_API_VERSION%                              ^
  -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a                                        ^
  -DCMAKE_MAKE_PROGRAM="%NINJA_ROOT%\ninja.exe"                             ^
  -DCMAKE_ANDROID_NDK="%ANDROID_NDK_HOME%"
```

**Note**: You will need to also set the following environment variables:
| Variable | Value |
| -------- | ----- |
| ANDROID_HOME | Path to your Android SDK installation |
| ANDROID_NDK_HOME | Path to your Android NDK installation |
| JAVA_HOME | Path to your Java SDK installation |
| JAVA_COMPILER | Path to the Java compiler |

**Note**: `CMAKE_SYSTEM_VERSION` is used to build a full path to `android.jar`, which needs to be linked against when generating the MPSS jar file. **Make sure this path exists**. The full path to `android.jar` is composed like this:
```cmd
%ANDROID_HOME%\platforms\android-%CMAKE_SYSTEM_VERSION%\android.jar
```

### Common Build Options

The following table outlines the common CMake configuration options recognized by the build system:

| Option | When set to `ON` |
|--------|-------------|
| `MPSS_BUILD_TESTS` | Build the test suite. |
| `MPSS_BUILD_MPSS_CORE_STATIC` | Build the core library as a static library. |
| `MPSS_BUILD_MPSS_CORE_SHARED` | Build the core library as a shared library. |
| `MPSS_BUILD_MPSS_OPENSSL_STATIC` | Build the OpenSSL provider as a static library. |
| `MPSS_BUILD_MPSS_OPENSSL_SHARED` | Build the OpenSSL provider as a shared library. |
| `BUILD_SHARED_LIBS` | Build all targets as shared libraries. |

Static targets are named `mpss::mpss_static` and `mpss::mpss_openssl_static`, whereas shared targets are `mpss::mpss` and `mpss::mpss_openssl`.
As usual, you can set `CMAKE_BUILD_TYPE` to set the build type (`Release`, `Debug`, etc.) when using a single-configuration generator.

## Using the MPSS Core Library

The MPSS core library provides a simple C++ API for creating, managing, and using cryptographic key pairs in secure storage. Here's how to get started:

### Basic Usage

```cpp
// Standard includes not shown here

#include "mpss/mpss.h"
using namespace mpss;

// Check if an algorithm is supported
if (!is_algorithm_supported(Algorithm::ecdsa_secp256r1_sha256)) {
    // Handle unsupported algorithm
    return;
}

// Create a new key pair
auto key_pair = KeyPair::Create("my-key", Algorithm::ecdsa_secp256r1_sha256);
if (!key_pair) {
    // Handle key creation failure
    std::string error = get_error();
    return;
}

// Sign some data
std::vector<std::byte> hash = /* your hash data */;
std::vector<std::byte> signature(key_pair->sign_hash_size());
std::size_t sig_len = key_pair->sign_hash(hash, signature);
if (sig_len == 0) {
    // Handle signing failure
    return;
}
signature.resize(sig_len);

// Verify the signature
bool is_valid = key_pair->verify(hash, signature);
```

### Key Management

```cpp
// Open an existing key pair
auto existing_key = KeyPair::Open("my-key");
if (!existing_key) {
    std::string error_msg = mpss::get_error();
    // Key doesn't exist or couldn't be opened
    // ...
    return;
}

// Extract the public key
std::vector<std::byte> public_key(existing_key->extract_key_size());
size_t key_len = existing_key->extract_key(public_key);
if (key_len == 0) {
    std::string error_msg = mpss::get_error();
    // Handle key extraction failure
    // ...
    return;
}
public_key.resize(key_len);

// Get key information
KeyInfo info = existing_key->key_info();
Algorithm alg = existing_key->algorithm();
AlgorithmInfo alg_info = existing_key->algorithm_info();

// Delete the key pair when no longer needed
bool deleted = existing_key->delete_key();
if (!deleted) {
    std::string error_msg = mpss::get_error();
    // Handle key deletion failure
    // ...
    return;
}
```

### Supported Algorithms

The library supports the following ECDSA algorithms:

| Algorithm | Key Size | Security Level | Hash Algorithm |
|-----------|----------|----------------|----------------|
| `ecdsa_secp256r1_sha256` | 256 bits | 128 bits | SHA-256 |
| `ecdsa_secp384r1_sha384` | 384 bits | 192 bits | SHA-384 |
| `ecdsa_secp521r1_sha512` | 521 bits | 256 bits | SHA-512 |

### Standalone Verification

You can also verify signatures without a key pair object using the standalone `verify` function:

```cpp
// Verify a signature with a public key
bool is_valid = verify(hash, public_key, Algorithm::ecdsa_secp256r1_sha256, signature);
```

### Error Handling

Use the `get_error()` function to retrieve detailed error information when operations fail:

```cpp
auto key_pair = KeyPair::Create("duplicate-name", Algorithm::ecdsa_secp256r1_sha256);
if (!key_pair) {
    std::string error_msg = get_error();
    std::cerr << "Key creation failed: " << error_message << std::endl;
}
```

### Platform-Dependent Behavior
There is a single known difference in how MPSS behaves on different platforms.
This happens when opening several instances of the same key.
Take the following code, for example:
```cpp
// Open an existing key pair
auto existing_key1 = KeyPair::Open("my-key");
auto existing_key2 = KeyPair::Open("my-key");

// Delete existing key
existing_key1->delete_key();

// Sign with the remaining KeyPair object
auto sig_size = existing_key2->sign_hash(hash, sig);
```
This code opens two instances of the same key and deletes the first one from the operating system.
- In Windows, the signing operation with ```existing_key2``` will succeed.
The Windows instance implementation holds a handle to the opened key, which will persist until closed, even if the underlying key representation has been deleted.
- In other platforms the operation will fail.
All other platform implementations hold only a reference to an in-memory cache that does not persist the key when it is deleted.

## OpenSSL Provider (mpss-openssl)

The MPSS OpenSSL provider enables seamless integration with OpenSSL 3.x applications by exposing MPSS functionality through the standard OpenSSL API. This allows existing OpenSSL-based applications to leverage hardware-backed secure key storage without code changes.

### Provider Components

The OpenSSL provider consists of several key components:

- **Provider Interface ([provider/provider.h](mpss-openssl/provider/provider.h) and [.cpp](mpss-openssl/provider/provider.cpp))** - Main provider registration and dispatch logic
- **Key Management ([provider/keymgmt.h](mpss-openssl/provider/keymgmt.h) and [.cpp](mpss-openssl/provider/keymgmt.cpp))** - Handles key generation, loading, and management operations
- **Signature Operations ([provider/signature.h](mpss-openssl/provider/signature.h) and [.cpp](mpss-openssl/provider/signature.cpp))** - Implements ECDSA and X.509 certificate signing using MPSS keys
- **Digest Operations ([provider/digest.h](mpss-openssl/provider/digest.h) and [.cpp](mpss-openssl/provider/digest.cpp))** - Wraps OpenSSL hash algorithm implementations
- **Encoder ([provider/encoder.h](mpss-openssl/provider/encoder.h) and [.cpp](mpss-openssl/provider/encoder.cpp))** - Handles key encoding and serialization for interoperability
- **Public API ([api.h](mpss-openssl/api.h) and [.cpp](mpss-openssl/api.cpp))** - Declaration of the `OSSL_provider_init` function, as well as C APIs for a few key management operations that are outside the purview of OpenSSL

### Using the OpenSSL Provider

The provider integrates with OpenSSL's standard EVP API. Here are a few common usage scenarios:

#### 1. Basic Key Generation and Signing

```cpp
#include <openssl/provider.h>
#include <openssl/evp.h>
// #include ...

// Load the MPSS provider and default provider
OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(libctx, "default");
OSSL_PROVIDER_add_builtin(libctx, "mpss", OSSL_provider_init);
OSSL_PROVIDER *mpss_prov = OSSL_PROVIDER_load(libctx, "mpss");

// Generate a key pair using OpenSSL API
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
EVP_PKEY_keygen_init(ctx);

// Set the MPSS key parameters
char *my_key_name = "my-openssl-key";
char *algorithm = "ecdsa_secp256r1_sha256";
OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string("key_name", my_key_name, 0),
    OSSL_PARAM_construct_utf8_string("mpss_algorithm", algorithm, 0),
    OSSL_PARAM_END};
EVP_PKEY_CTX_set_params(ctx, params);

EVP_PKEY *pkey = nullptr;
EVP_PKEY_generate(ctx, &pkey);
if (!pkey) {
    // You can read errors with mpss_get_error
    const char *error_msg = mpss_get_error();
    fprintf(stderr, "Error: %s\n", error_msg);
}
EVP_PKEY_CTX_free(ctx);

// Sign data using standard OpenSSL operations
EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=mpss");
EVP_PKEY_sign_init(sign_ctx);
// ... perform signing operations

// Close the key but note that it is not deleted
EVP_PKEY_free(pkey);
```

#### 2. Opening Existing Keys and Public Key Extraction

```cpp
// Open an existing MPSS key by name
EVP_PKEY_CTX *load_ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=mpss");
EVP_PKEY_fromdata_init(load_ctx);

OSSL_PARAM load_params[] = {
    OSSL_PARAM_construct_utf8_string("key_name", my_key_name, 0),
    OSSL_PARAM_END};

EVP_PKEY *existing_pkey = nullptr;
EVP_PKEY_fromdata(load_ctx, &existing_pkey, EVP_PKEY_KEYPAIR, load_params);
EVP_PKEY_CTX_free(load_ctx);

// Extract the raw public key
std::size_t public_key_len = 1024;
std::vector<unsigned char> public_key(public_key_len);
EVP_PKEY_get_raw_public_key(existing_pkey, public_key.data(), &public_key_len);
public_key.resize(public_key_len);

// Or directly extract the public key (SPKI) in PEM format.
BIO *pk_file = BIO_new_file("pk.pem", "w");
PEM_write_bio_PUBKEY_ex(pk_file, public_key, mpss_libctx, "provider=mpss"));
BIO_free(pk_file);
```

#### 3. Self-Signed Certificate Creation

```cpp
// Assuming pkey (an EVP_PKEY) holds a key pair in the MPSS provider...

// Create a self-signed certificate using a secret key in the MPSS provider
X509 *cert = X509_new_ex(libctx, "provider=mpss");
X509_set_version(cert, 2);  // X.509 v3
ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
X509_gmtime_adj(X509_get_notBefore(cert), 0);           // Valid from now
X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);    // Valid for 1 year
X509_set_pubkey(cert, pkey);

// Set subject and issuer names (same for self-signed)
X509_NAME *name = X509_get_subject_name(cert);
X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"My Organization", -1, -1, 0);
X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"my-server.example.com", -1, -1, 0);
X509_set_issuer_name(cert, name);  // Same as subject for self-signed

// Sign the certificate with its own key; make sure to use the correct hash
// function here, corresponding to the MPSS key type.
X509_sign(cert, pkey, EVP_sha256());

// Verify the self-signed certificate
X509_verify(cert, pkey);
```

#### 4. Certificate Authority and Certificate Chain Creation

A complete end-to-end example of creating a CA certificate with an MPSS-backed key and signing end-entity certificates with it is shown in [tests/mpss_openssl_e2e_test.cpp](tests/mpss_openssl_e2e_test.cpp).

#### 5. Secure Key Cleanup

When an MPSS secret key is no longer needed, it can be securely deleted from the secure environment as follows:

```cpp
#include "mpss-openssl/api.h"

const char *ca_key_name = "my-old-key";
bool deletion_success = mpss_delete_key(ca_key_name);
if (deletion_success) {
    printf("MPSS CA key '%s' successfully deleted from secure storage\n", ca_key_name);
} else {
    const char *error_msg = mpss_get_error();
    printf("Failed to delete MPSS key '%s': %s\n", ca_key_name, error_msg);
}
```

**Important notes:**
- Only delete keys when you are certain they are no longer needed for signing operations.
There is no way to bring back deleted secret keys.
- Existing certificates remain valid when a secret key deleted and can still be verified using the public key.
- It may not be easy to list existing keys (or rather, their "names") in the secure environment.
MPSS does not provide such functionality, but individual operating systems might have APIs for enumerating the storage content identifiers.

### Building mpss-openssl 

To build the OpenSSL provider, configure the CMake project with one of:

- `MPSS_BUILD_MPSS_OPENSSL_STATIC=ON` for a static library build
- `MPSS_BUILD_MPSS_OPENSSL_SHARED=ON` for a shared library build

Building for iOS requires extra care.
For instructions, see [the example above](README#iOS).

### Examples and Testing

Comprehensive usage examples can be found in [`tests/mpss_openssl_tests.cpp`](tests/mpss_openssl_tests.cpp) and especially in [`tests/mpss_openssl_e2e_test.cpp`](tests/mpss_openssl_e2e_test.cpp).
These demonstrate:

- Provider registration and initialization
- Key generation with named keys
- Digital signing and verification operations
- X.509 certificate creation and validation
- Key deletion and cleanup

The tests are built automatically when `MPSS_BUILD_TESTS=ON` is set, provided the OpenSSL provider is also being built.

## Contributing to MPSS

MPSS is released under the MIT license.
We welcome contributions, including feature additions and bug fixes.
If you have a feature request or a question about how to use the library, please [submit an issue](https://github.com/microsoft/mpss/issues).

