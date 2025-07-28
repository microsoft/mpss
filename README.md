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
Generating an Xcode project is recommended for iOS. After generating the project, it can simply be added to a different Xcode project as a Framework. Another benefit of generating an Xcode project is that you don't have to worry about targeting either the iPhone Simulator or a real iPhone. Xcode will take care of this.
The command to generate an Xcode project is the following:

```bash
cmake -S . -B build -GXcode -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_DEPLOYMENT_TARGET=$IPHONE_SDK_VERSION -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO -DCMAKE_IOS_INSTALL_COMBINED=YES
```

In order to find out what iPhone SDKs are installed, you can run the following command:

```bash
xcodebuild -showsdks
```

This will show all installed SDKs. If the SDK appears as `iOS 18.4`, for example, you would need to specify `-DCMAKE_OSX_DEPLOYMENT_TARGET=18.4`.


### Android
Generate Ninja build files for cross compiling to the x64 Android simulator. The vcpkg toolchain file is specified to satisfy build dependencies of MPSS.

```cmd
cmake -S . -B buildX64 -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-android -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=%ANDROID_API_VERSION% -DCMAKE_ANDROID_ARCH_ABI=x86_64 -GNinja -DCMAKE_MAKE_PROGRAM=%NINJA_ROOT%\ninja.exe -DCMAKE_ANDROID_NDK=%ANDROID_NDK_HOME%
```

Generate Ninja build files for cross compiling to Arm64.

```cmd
cmake -S . -B buildArm -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=arm64-android -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=%ANDROID_API_VERSION% -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a -GNinja -DCMAKE_MAKE_PROGRAM=%NINJA_ROOT%\ninja.exe -DCMAKE_ANDROID_NDK=%ANDROID_NDK_HOME%
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
    // Key doesn't exist or couldn't be opened
    return;
}

// Extract the public key
std::vector<std::byte> public_key(existing_key->extract_key_size());
size_t key_len = existing_key->extract_key(public_key);
if (key_len == 0) {
    // Handle key extraction failure
    return;
}
public_key.resize(key_len);

// Get key information
KeyInfo info = existing_key->key_info();
Algorithm alg = existing_key->algorithm();
AlgorithmInfo alg_info = existing_key->algorithm_info();

// Delete the key pair when no longer needed
existing_key->delete_key();
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
    std::string error_message = get_error();
    std::cerr << "Key creation failed: " << error_message << std::endl;
}
```

## OpenSSL Provider (mpss-openssl)

The MPSS OpenSSL provider enables seamless integration with OpenSSL 3.x applications by exposing MPSS functionality through the standard OpenSSL API. This allows existing OpenSSL-based applications to leverage hardware-backed secure key storage without code changes.

### Provider Components

The OpenSSL provider consists of several key components:

- **Provider Interface ([provider.h](mpss-openssl/provider/provider.h) and [.cpp](mpss-openssl/provider/provider.cpp))** - Main provider registration and dispatch logic
- **Key Management ([keymgmt.h](mpss-openssl/provider/keymgmt.h) and [.cpp](mpss-openssl/provider/keymgmt.cpp))** - Handles key generation, loading, and management operations
- **Signature Operations ([signature.h](mpss-openssl/provider/signature.h) and [.cpp](mpss-openssl/provider/signature.cpp))** - Implements ECDSA signing and verification using MPSS keys
- **Digest Operations ([digest.h](mpss-openssl/provider/digest.h) and [.cpp](mpss-openssl/provider/digest.cpp))** - Wraps OpenSSL hash algorithm implementations
- **Encoder ([encoder.h](mpss-openssl/provider/encoder.h) and [.cpp](mpss-openssl/provider/encoder.cpp))** - Handles key encoding and serialization for interoperability
- **Public API (`api.h`)** - Declaration of the `OSSL_provider_init` function, as well as C APIs for a few key management operations that are outside the purview of OpenSSL

### Using the OpenSSL Provider

The provider integrates with OpenSSL's standard EVP API. Here are three common usage scenarios:

#### 1. Basic Key Generation and Signing

```cpp
// Standard includes not shown here

#include <openssl/provider.h>
#include <openssl/evp.h>

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
std::vector<unsigned char> public_key;
std::size_t public_key_len = 1024;
public_key.resize(public_key_len);
EVP_PKEY_get_raw_public_key(existing_pkey, public_key.data(), &public_key_len);
public_key.resize(public_key_len);

// Or get the public key in DER format (SubjectPublicKeyInfo)
OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(
    existing_pkey, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", "provider=mpss");
unsigned char *spki_der = nullptr;
std::size_t spki_der_len = 0;
OSSL_ENCODER_to_data(ectx, &spki_der, &spki_der_len);
OSSL_ENCODER_CTX_free(ectx);
```

#### 3. Self-Signed Certificate Creation

This example shows how to create a self-signed certificate using an MPSS key:

```cpp
// Create a self-signed certificate using the MPSS key
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

// Sign the certificate with its own key
X509_sign(cert, pkey, EVP_sha256());

// Verify the self-signed certificate
X509_verify(cert, pkey);
```

#### 4. Certificate Authority and Certificate Chain Creation

This example shows how to use an MPSS key as a Certificate Authority to sign certificates for other keys:

```cpp
// Create a CA certificate using the MPSS key
X509 *ca_cert = X509_new_ex(libctx, "provider=mpss");
X509_set_version(ca_cert, 2);  // X.509 v3
ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);
X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);           // Valid from now
X509_gmtime_adj(X509_get_notAfter(ca_cert), 31536000L);    // Valid for 1 year
X509_set_pubkey(ca_cert, pkey);

// Set subject and issuer names (same for self-signed CA)
X509_NAME *ca_name = X509_get_subject_name(ca_cert);
X509_NAME_add_entry_by_txt(ca_name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
X509_NAME_add_entry_by_txt(ca_name, "O", MBSTRING_ASC, (unsigned char*)"My CA", -1, -1, 0);
X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, (unsigned char*)"My CA", -1, -1, 0);
X509_set_issuer_name(ca_cert, ca_name);

// Add CA extensions (required for proper CA certificates)
X509V3_CTX ext_ctx;
X509V3_set_ctx(&ext_ctx, ca_cert, ca_cert, nullptr, nullptr, 0);

// Add Basic Constraints: critical, CA:TRUE
X509_EXTENSION *basic_ext = X509V3_EXT_conf_nid(nullptr, &ext_ctx, NID_basic_constraints, "critical,CA:TRUE");
X509_add_ext(ca_cert, basic_ext, -1);
X509_EXTENSION_free(basic_ext);

// Add Key Usage: critical, keyCertSign and cRLSign
X509_EXTENSION *usage_ext = X509V3_EXT_conf_nid(nullptr, &ext_ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
X509_add_ext(ca_cert, usage_ext, -1);
X509_EXTENSION_free(usage_ext);

// Sign the CA certificate
X509_sign(ca_cert, pkey, EVP_sha256());

// Now create a subordinate certificate for another key and sign it with the MPSS CA
// Generate an RSA key for the end-entity certificate (using default provider)
EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", nullptr);
EVP_PKEY_keygen_init(rsa_ctx);
EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 3072);
EVP_PKEY *rsa_pkey = nullptr;
EVP_PKEY_keygen(rsa_ctx, &rsa_pkey);
EVP_PKEY_CTX_free(rsa_ctx);

// Create the end-entity certificate
X509 *end_cert = X509_new_ex(libctx, "provider=mpss");
X509_set_version(end_cert, 2);
ASN1_INTEGER_set(X509_get_serialNumber(end_cert), 2);  // Different serial number
X509_gmtime_adj(X509_get_notBefore(end_cert), 0);
X509_gmtime_adj(X509_get_notAfter(end_cert), 31536000L);
X509_set_pubkey(end_cert, rsa_pkey);  // Use the RSA public key

// Set subject (different from CA) but same issuer (the CA)
X509_NAME *end_name = X509_get_subject_name(end_cert);
X509_NAME_add_entry_by_txt(end_name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
X509_NAME_add_entry_by_txt(end_name, "O", MBSTRING_ASC, (unsigned char*)"End Entity", -1, -1, 0);
X509_NAME_add_entry_by_txt(end_name, "CN", MBSTRING_ASC, (unsigned char*)"End Entity", -1, -1, 0);
X509_set_issuer_name(end_cert, ca_name);  // Issued by the CA

// Sign the end-entity certificate with the MPSS CA key
X509_sign(end_cert, pkey, EVP_sha256());  // pkey is the MPSS CA key

// Verify the certificate chain
X509_verify(end_cert, pkey);  // Verify end cert was signed by CA

// Serialize the certificate chain and public key to files
// Save CA certificate
BIO *ca_file = BIO_new_file("ca.pem", "w");
PEM_write_bio_X509(ca_file, ca_cert);
BIO_free(ca_file);

// Save end-entity certificate
BIO *end_file = BIO_new_file("end_cert.pem", "w");
PEM_write_bio_X509(end_file, end_cert);
BIO_free(end_file);

// Save the MPSS CA public key (used to verify the root CA certificate)
BIO *pubkey_file = BIO_new_file("ca_pubkey.pem", "w");
PEM_write_bio_PUBKEY(pubkey_file, pkey);
BIO_free(pubkey_file);

// Clean up
X509_free(ca_cert);
X509_free(end_cert);
EVP_PKEY_free(rsa_pkey);
```

#### Certificate Chain Verification with Serialized Keys

Once you have serialized certificates and public keys, you can verify them independently:

```cpp
// Load CA certificate from file
BIO *ca_load_bio = BIO_new_file("ca.pem", "r");
X509 *loaded_ca_cert = PEM_read_bio_X509(ca_load_bio, nullptr, nullptr, nullptr);
BIO_free(ca_load_bio);

// Load end-entity certificate from file
BIO *end_load_bio = BIO_new_file("end_cert.pem", "r");
X509 *loaded_end_cert = PEM_read_bio_X509(end_load_bio, nullptr, nullptr, nullptr);
BIO_free(end_load_bio);

// Load the MPSS public key from file
BIO *pubkey_load_bio = BIO_new_file("ca_pubkey.pem", "r");
EVP_PKEY *loaded_pubkey = PEM_read_bio_PUBKEY(pubkey_load_bio, nullptr, nullptr, nullptr);
BIO_free(pubkey_load_bio);

// Verify the CA certificate is self-signed using the MPSS public key
X509_verify(loaded_ca_cert, loaded_pubkey);

// Verify the end-entity certificate was signed by the CA
X509_verify(loaded_end_cert, loaded_pubkey);

// Clean up
X509_free(loaded_ca_cert);
X509_free(loaded_end_cert);
EVP_PKEY_free(loaded_pubkey);
```

#### Command Line Verification with OpenSSL

The above code creates three files that can be verified using the standard OpenSSL command-line tool:

- `ca.pem` - The self-signed CA certificate (signed with the MPSS private key)
- `end_cert.pem` - The end-entity certificate (signed by the MPSS CA key)
- `ca_pubkey.pem` - The MPSS CA public key (extracted from the hardware-backed private key)

```bash
# Verify the self-signed CA certificate using the exported public key
openssl verify -CAfile ca.pem -check_ss_sig ca.pem

# Verify the end-entity certificate against the CA
openssl verify -CAfile ca.pem end_cert.pem

# Extract public key from the CA certificate and compare with our exported key
openssl x509 -in ca.pem -pubkey -noout > extracted_pubkey.pem
diff ca_pubkey.pem extracted_pubkey.pem

# Display certificate chain information
openssl x509 -in ca.pem -text -noout -subject -issuer
openssl x509 -in end_cert.pem -text -noout -subject -issuer

# Verify with verbose output
openssl verify -verbose -CAfile ca.pem end_cert.pem
```

On Windows PowerShell:

```powershell
# Verify certificates
openssl verify -CAfile ca.pem -check_ss_sig ca.pem
openssl verify -CAfile ca.pem end_cert.pem

# Compare public keys to ensure they match
openssl x509 -in ca.pem -pubkey -noout | Out-File -Encoding ascii extracted_pubkey.pem
Compare-Object (Get-Content ca_pubkey.pem) (Get-Content extracted_pubkey.pem)
```

#### Secure Key Cleanup

When the MPSS secret key is no longer needed, it can be securely deleted from hardware storage as follows:

```cpp
#include "mpss-openssl/api.h"

// Check if the key exists before attempting deletion
const char *ca_key_name = "my-ca-key";
if (mpss_is_valid_key(ca_key_name)) {
    // Delete the MPSS private key from secure storage
    bool deletion_success = mpss_delete_key(ca_key_name);
    if (deletion_success) {
        printf("MPSS CA key '%s' successfully deleted from secure storage\n", ca_key_name);
    } else {
        printf("Failed to delete MPSS CA key '%s'\n", ca_key_name);
    }
} else {
    printf("MPSS CA key '%s' not found in secure storage\n", ca_key_name);
}

// The certificates and public key files remain valid for verification
// but the private key is permanently removed from hardware storage
```

**Important Security Notes:**
- Once deleted, the MPSS private key cannot be recovered
- Existing certificates remain valid and can still be verified using the public key
- The certificates can continue to be used for verification purposes
- Only delete keys when you're certain they're no longer needed for signing operations
- Consider key rotation policies before permanent deletion

### Key Features

- **Standard OpenSSL API** - No changes required to existing OpenSSL-based applications
- **Hardware-Backed Storage** - Keys are stored securely using platform-specific secure storage
- **Certificate Generation** - Support for X.509 certificate creation with MPSS keys
- **Cross-Platform** - Works on Windows, macOS, iOS, and Android through the same API
- **Digest Algorithms** - Built-in support for SHA-256, SHA-384, and SHA-512

### Building the Provider

To build the OpenSSL provider, configure the CMake project with:

- `MPSS_BUILD_MPSS_OPENSSL_STATIC=ON` for a static library build
- `MPSS_BUILD_MPSS_OPENSSL_SHARED=ON` for a shared library build

### Examples and Testing

Comprehensive usage examples can be found in [`tests/mpss_openssl_tests.cpp`](tests/mpss_openssl_tests.cpp), which demonstrate:

- Provider registration and initialization
- Key generation with named keys
- Digital signing and verification operations
- X.509 certificate creation and validation
- Digest algorithm usage
- Integration with OpenSSL's EVP API

The tests are built automatically when `MPSS_BUILD_TESTS=ON` is set, provided the OpenSSL provider is also being built.

## Contributing to MPSS

MPSS is released under the MIT license.
We welcome contributions, including feature additions and bug fixes.
If you have a feature request or a question about how to use the library, please [submit an issue](https://github.com/microsoft/mpss/issues).