# MPSS - A Multi-Platform Secure Signing Library

MPSS provides a C++20 API for creating, storing, and using signing keys without exporting their
private material. An OpenSSL provider exposes the same keys to OpenSSL 3.2 and later.

| Platform | API |
|----------|-----|
| Windows | TPM-backed [MS_PLATFORM_KEY_STORAGE_PROVIDER](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider) if available; [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) otherwise; software-protected storage if neither |
| macOS / iOS | [Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave) for P-256 when available; [Keychain](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain) for P-384/P-521 or when the Secure Enclave is unavailable |
| Android | [AndroidKeyStore](https://developer.android.com/privacy-and-security/keystore), requesting StrongBox for P-256 first; otherwise protection depends on the device and may be TEE-backed or software |
| Linux | [YubiKey PIV](https://developers.yubico.com/PIV/) (default, see below) |
| YubiKey (optional) | [YubiKey PIV](https://developers.yubico.com/PIV/) (cross-platform: Windows, macOS, Linux only) |

Enable YubiKey support with `MPSS_BACKEND_YUBIKEY=ON`. It is optional on Windows/macOS,
required on Linux, and unsupported on iOS/Android.

**Windows protection is per key.** Creation tries TPM, VBS, then software storage; unsupported
TPM algorithms can fall back without leaving an error. There is no minimum-storage-tier
parameter. Read `key_info().storage_description` for `"TPM Protection"`,
`"Virtualization Based Security"`, or `"Software Protection"`.
`is_hardware_backed` is **true for both TPM and VBS keys**: VBS isolation is not TPM key storage.

## Compiling for different platforms

The OS-native core uses system APIs. Additional dependencies are supplied by vcpkg:
[GoogleTest](https://github.com/google/googletest) for tests,
[libykpiv](https://developers.yubico.com/yubico-piv-tool/) and OpenSSL for YubiKey support,
and [OpenSSL](https://github.com/openssl/openssl) 3.2 or later for the provider.

The [vcpkg port](ports/mpss/) targets desktop platforms. Build iOS and Android directly from
source as described below; those builds also use vcpkg for dependencies.

### Using CMake Presets

Install [vcpkg](https://github.com/microsoft/vcpkg), set `VCPKG_ROOT`, and choose a
[CMake preset](CMakePresets.json):

```bash
cmake -S . --preset <configure-preset-name>
cmake --build --preset <build-preset-name>
cmake --install out/build/<configure-preset-name> --prefix <destination> # optional
```

Run `cmake --list-presets=all` to list presets. Desktop names containing `-with-yubikey` enable
YubiKey support; `-shared` selects shared libraries, otherwise static. Android uses shared
libraries and the iOS Simulator preset uses static libraries. Linux offers only `-with-yubikey`
presets, because it has no OS-native backend and MPSS requires at least one backend.

Each configure preset has a separate `out/build/<name>` directory and vcpkg installation.
With Visual Studio or Xcode, add `--config Debug` or `--config Release` when installing.
Linux presets target the host architecture; Windows, macOS, Android, and iOS presets name
their target architecture.

### Configuring Without Presets

On Windows:

```cmd
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
```

On macOS:

```bash
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
```

Linux has no OS-native backend, so the YubiKey backend is not optional there: configuration fails
with `No backend available` unless it is enabled.

```bash
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DMPSS_BACKEND_YUBIKEY=ON
```

See [YubiKey Backend](#yubikey-backend) for its prerequisites, which on Linux include a system
PC/SC library.

### iOS

Build iOS XCFrameworks with the provided script:

```bash
# Core library + OpenSSL provider (default):
cmake -P cmake/ios_xcframework.cmake

# Core library only (without OpenSSL provider):
cmake -DBUILD_MPSS_OPENSSL=OFF -P cmake/ios_xcframework.cmake

# Debug build, custom output directory:
cmake -DBUILD_TYPE=Debug -DOUTPUT_DIR=./out -P cmake/ios_xcframework.cmake
```

The script creates `libmpss.xcframework` and optionally `libmpss-openssl.xcframework` in the
project root, with arm64 slices for iOS devices and the Apple Silicon iOS simulator.

Add the XCFrameworks to your Xcode project.

If you include the provider, your app must also link an OpenSSL built for the iOS target. The
provider archive deliberately leaves OpenSSL's symbols undefined so that your own link step
resolves them, which is also why one set of headers serves both the device and simulator slices.
Building OpenSSL for iOS through vcpkg is the usual route; the macOS OpenSSL on your build host
will not link against an iOS binary.

The MPSS core API is C++, so call it from C++ or Objective-C++. Swift cannot import it directly
and needs a small Objective-C++ wrapper.

For other Apple platforms, build directly with the appropriate `CMAKE_SYSTEM_NAME`,
`CMAKE_OSX_SYSROOT`, and `CMAKE_OSX_ARCHITECTURES`, then bundle the resulting `.a` files into
your own XCFramework.

<details>
<summary>Manual build steps (without the script)</summary>

```bash
D=out/ios-xcframework  # working directory

# Configure for separate build directories.
cmake -S . -B $D/build-device -GXcode                                       \
    -DCMAKE_SYSTEM_NAME=iOS                                                 \
    -DCMAKE_OSX_SYSROOT=iphoneos                                            \
    -DCMAKE_OSX_ARCHITECTURES=arm64                                         \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"   \
    -DMPSS_BUILD_MPSS_CORE_STATIC=ON                                        \
    -DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON # only if building also mpss-openssl
cmake -S . -B $D/build-simulator -GXcode                                    \
    -DCMAKE_SYSTEM_NAME=iOS                                                 \
    -DCMAKE_OSX_SYSROOT=iphonesimulator                                     \
    -DCMAKE_OSX_ARCHITECTURES=arm64                                         \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"   \
    -DMPSS_BUILD_MPSS_CORE_STATIC=ON                                        \
    -DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON # only if building also mpss-openssl

# Build and install.
cmake --build $D/build-device --config Release -j
cmake --build $D/build-simulator --config Release -j
cmake --install $D/build-device --config Release --prefix $D/install-device
cmake --install $D/build-simulator --config Release --prefix $D/install-simulator

# Stage headers per platform (config.h may differ between device and simulator).
mkdir -p $D/staging/mpss/{device,simulator}
rsync -a $D/install-device/include/mpss $D/staging/mpss/device/
rsync -a $D/install-simulator/include/mpss $D/staging/mpss/simulator/

# Only if building also mpss-openssl.
mkdir -p $D/staging/mpss-openssl/{device,simulator}
rsync -a $D/install-device/include/mpss-openssl $D/staging/mpss-openssl/device/
rsync -a $D/install-simulator/include/mpss-openssl $D/staging/mpss-openssl/simulator/
rsync -a $D/build-device/vcpkg_installed/arm64-ios/include/openssl $D/staging/mpss-openssl/device
rsync -a $D/build-simulator/vcpkg_installed/arm64-ios/include/openssl $D/staging/mpss-openssl/simulator

# Create an XCFramework for mpss.
xcodebuild -create-xcframework                                              \
    -library $D/install-device/lib/libmpss_static.a                         \
    -headers $D/staging/mpss/device                                         \
    -library $D/install-simulator/lib/libmpss_static.a                      \
    -headers $D/staging/mpss/simulator                                      \
    -output libmpss.xcframework

# Only if building also mpss-openssl.
xcodebuild -create-xcframework                                              \
    -library $D/install-device/lib/libmpss_openssl_static.a                 \
    -headers $D/staging/mpss-openssl/device                                 \
    -library $D/install-simulator/lib/libmpss_openssl_static.a              \
    -headers $D/staging/mpss-openssl/simulator                              \
    -output libmpss-openssl.xcframework
```

</details>

#### Running the iOS simulator suite

The iOS tests use a hosted XCTest bundle. The simulator exercises Keychain storage, not Secure
Enclave. On an Apple Silicon Mac, build the suite with the iOS 16.3 deployment target:

```bash
export VCPKG_ROOT=/absolute/path/to/vcpkg

cmake --preset ios-simulator-arm64-debug
cmake --build --preset ios-simulator-arm64-debug \
  --target mpss_ios_xctest
```

List the destinations supported by the generated scheme:

```bash
xcodebuild \
  -project out/build/ios-simulator-arm64-debug/mpss.xcodeproj \
  -scheme mpss_ios_test_host \
  -showdestinations
```

Select an arm64 iPhone Simulator UDID from that output, then boot it if necessary and wait until it
is ready:

```bash
xcrun simctl bootstatus <simulator-udid> -b
```

Run the tests with:

```bash
xcodebuild \
  -project out/build/ios-simulator-arm64-debug/mpss.xcodeproj \
  -scheme mpss_ios_test_host \
  -configuration Debug \
  -destination "platform=iOS Simulator,id=<simulator-udid>" \
  -parallel-testing-enabled NO \
  test
```

#### Running on a physical iOS device

Use a physical device to exercise Secure Enclave. Configure the device build, then select your
development team and provisioning profile in Xcode:

```bash
cmake -S . -B /path/to/build-ios-device -G Xcode \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=16.3 \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=arm64-ios \
  -DMPSS_BUILD_MPSS_CORE_STATIC=ON \
  -DMPSS_BUILD_MPSS_OPENSSL_STATIC=ON \
  -DMPSS_BUILD_TESTS=ON \
  -DMPSS_IOS_TEST_BUNDLE_IDENTIFIER=com.yourdomain.mpss.tests
```

Replace `com.yourdomain.mpss.tests` with a reverse-DNS identifier that your development team can
sign. The XCTest bundle uses the same identifier with `.xctest` appended.

Open `mpss.xcodeproj`, configure signing for `mpss_ios_test_host`, confirm
`mpss_ios_xctest` appears in the host scheme's Test action, choose the connected device, and run the
Test action. The test host carries a Keychain access-group entitlement derived from its signed
application identifier.

### Android

The `android-base` preset selects the compile API, Build Tools, and NDK versions. Android
requires API 28 or later and JDK 21; builds use Java 17 bytecode and shared native libraries.
Set `ANDROID_HOME`, `JAVA_HOME`, and `VCPKG_ROOT`, then build for arm64:

```bash
cmake --preset android-arm64-release
cmake --build --preset android-arm64-release

cmake --install out/build/android-arm64-release --prefix out/install/android-arm64-release
```

Use `android-x64-release` for x86_64. Debug variants are `android-x64-debug` and
`android-arm64-debug`.

The presets require the following environment variables:

| Variable | Value |
| -------- | ----- |
| ANDROID_HOME | Path to your Android SDK installation |
| JAVA_HOME | Path to your JDK 21 installation |
| VCPKG_ROOT | Path to your vcpkg installation |

Install the SDK packages selected by `android-base` with:

```bash
cmake -P scripts/bootstrap_android_sdk.cmake
```

Run this after installing Android's command-line tools and when the preset's SDK requirements
change; normal builds do not install SDK packages. `CMAKE_SYSTEM_VERSION` sets the minimum
runtime API, while `MPSS_ANDROID_COMPILE_API` selects the Java compile API.

P-256 key creation first requests StrongBox and falls back to AndroidKeyStore when StrongBox is
unavailable. Before API level 31, hardware-backed storage is reported as `Unknown Secure`; API
level 31 and later report the specific Android security level.

Use devices receiving current security updates; API compatibility alone does not establish security.

The Android presets enable the shared OpenSSL provider and the test suite. Pass
`-DMPSS_BUILD_MPSS_OPENSSL_SHARED=OFF` or `-DMPSS_BUILD_TESTS=OFF` after the preset name for a
smaller library-only build.

MPSS and its consumers must use the same NDK and `libc++_shared.so`. Top-level MPSS builds
select and install that runtime automatically. Consumers using `add_subdirectory()` or
`find_package()` must select it before CMake enables C++; MPSS fails configuration rather than
allowing a mixed-runtime process. With Gradle's `externalNativeBuild`:

```groovy
android {
    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments "-DANDROID_STL=c++_shared"
            }
        }
    }
}
```

For CMake's native Android toolchain, use `-DCMAKE_ANDROID_STL_TYPE=c++_shared` instead.

The native target can then link to the exported MPSS target normally:

```cmake
find_package(mpss CONFIG REQUIRED)

add_library(app_native SHARED app_native.cpp)
target_link_libraries(app_native PRIVATE mpss::mpss)
```

Package one `libc++_shared.so` per ABI. Gradle supplies it for `externalNativeBuild`; do not also
copy it into `jniLibs`. Include `mpss.jar` as a Java dependency.

Initialize MPSS's Java bridge before calling native code:

```java
static
{
    System.loadLibrary("mpss");
    System.loadLibrary("app_native");
}
```

Load `mpss` before the application library so `JNI_OnLoad` runs with the application's class
loader. Native `dlopen` or loading MPSS only as a dependency is not sufficient. Use `mpss_debug`
instead when packaging the default Debug library.

#### Running the Android tests

Android tests run inside an instrumentation APK. Build it for an arm64 device with:

```bash
cmake --preset android-arm64-debug
cmake --build --preset android-arm64-debug
```

This creates `out/build/android-arm64-debug/android-tests/mpss-tests.apk`. Use the
`android-x64-debug` preset and matching build directory for an x86_64 emulator.

The build packages the Java classes, native libraries, and shared C++ runtime using the
checked-in Gradle wrapper.

For a physical device, enable Developer options and USB debugging, connect the device, and accept
the computer authorization prompt on the device. Confirm that Android Debug Bridge lists it with
the `device` status rather than `unauthorized`:

```bash
adb devices
adb shell getprop ro.product.cpu.abi
```

The device ABI must match the build. Install and run the APK:

```bash
adb install -r out/build/android-arm64-debug/android-tests/mpss-tests.apk
adb logcat -c
adb shell am instrument -w com.microsoft.mpss.tests/.TestRunner
adb logcat -d -s MPSS:V MPSS_TESTS:V '*:S'
```

`MPSS` contains library trace and error messages; `MPSS_TESTS` contains GoogleTest events and the
final pass, skip, and failure counts.

The test APK is signed with Gradle's local debug key. If an APK with the same application ID but a
different signing key is already installed, remove it first with
`adb uninstall com.microsoft.mpss.tests`.

Emulators exercise AndroidKeyStore and JNI integration; TEE and StrongBox require physical-device testing.

After building and installing, you will find:
- `lib/libmpss.so` — the native shared library.
- `lib/mpss.jar` — the Java classes for the JNI bridge (`KeyManagement`, `Algorithm`, etc.).
- `lib/libc++_shared.so` — the matching NDK C++ runtime.
- When the OpenSSL provider is enabled, `lib/libmpss_openssl.so`.

To use prebuilt MPSS binaries through an Android Studio project's `jniLibs`:
1. Copy `libmpss.so` to `app/src/main/jniLibs/<abi>/` (e.g., `arm64-v8a/` or `x86_64/`).
2. Copy `mpss.jar` to `app/libs/`.
3. Add the JAR as a file dependency in your module's `build.gradle`.
4. If using the OpenSSL provider, copy `libmpss_openssl.so` beside `libmpss.so`.

Without `externalNativeBuild`, also copy `libc++_shared.so` from the same installation into
`jniLibs/<abi>/`. Otherwise, let Gradle package it.

**Note**: Only shared libraries are supported on Android. Static builds will produce a configuration error.

### YubiKey Backend

Unlike the sections above, this is an optional backend rather than a platform. It is available on
Linux, macOS, and Windows, so the build steps below cover all three.

#### Prerequisites

The YubiKey backend requires a PIV-capable YubiKey with the PIV application enabled and firmware
support for [reading slot metadata](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/metadata.html).
Install the `ykman` CLI separately for device administration. FIPS models also need
[FIPS provisioning](#fips-device-readiness).

On **Linux**, the PC/SC smart card library must be installed separately, as it is a system dependency:

```bash
# Debian/Ubuntu
sudo apt install libpcsclite-dev

# Fedora/RHEL
sudo dnf install pcsc-lite-devel
```

At runtime, a working PC/SC service (normally `pcscd` on Linux) and permission to access the
reader are required as well.

#### Build Configuration

- **Linux:**
  ```bash
  cmake --preset linux-with-yubikey-release
  cmake --build --preset linux-with-yubikey-release
  ```

- **macOS:**
  ```bash
  cmake --preset macos-arm64-with-yubikey-release
  cmake --build --preset macos-arm64-with-yubikey-release
  ```

  Use `macos-x64-...` for x64. The presets target macOS 13.3 or later.

- **Windows:**
  ```cmd
  cmake --preset win-vs2022-x64-with-yubikey
  cmake --build --preset win-vs2022-x64-with-yubikey-release
  ```

For device setup and backend selection, see [Using MPSS with YubiKey PIV](#using-mpss-with-yubikey-piv).

### Common Build Options

| Option | Description |
|--------|-------------|
| `MPSS_BUILD_TESTS=ON` | Build the test suite. |
| `MPSS_BUILD_WIN32_MOCK_TESTS=ON` | Also build the separate NCrypt failure-injection executable on Windows; requires `MPSS_BUILD_TESTS=ON` and a static core build. |
| `MPSS_BUILD_MPSS_CORE_STATIC=ON` | Build the core library as a static library. |
| `MPSS_BUILD_MPSS_CORE_SHARED=ON` | Build the core library as a shared library. |
| `MPSS_BUILD_MPSS_OPENSSL_STATIC=ON` | Build the OpenSSL provider as a static library. |
| `MPSS_BUILD_MPSS_OPENSSL_SHARED=ON` | Build the OpenSSL provider as a shared library. |
| `MPSS_BACKEND_YUBIKEY=ON` | Enable the YubiKey PIV backend. |
| `MPSS_ENABLE_HARDENING=OFF` | Disable security hardening compile and link flags (default is `ON`). |
| `BUILD_SHARED_LIBS=ON` | Select shared core and provider libraries when no explicit MPSS library-type option is enabled. Explicit options take precedence. |

Static targets are named `mpss::mpss_static` and `mpss::mpss_openssl_static`, whereas shared targets are `mpss::mpss` and `mpss::mpss_openssl`.
Single-configuration generators use `CMAKE_BUILD_TYPE` to select `Debug` or `Release`.
Building the tests does not run them. On desktop builds, run `bin/mpss_tests` from the build
directory (`bin\Debug\mpss_tests.exe` or `bin\Release\mpss_tests.exe` with Visual Studio).
When enabled, run `mpss_win32_mock_tests.exe` separately from the same configuration directory.
Shared-core builds do **not** create that mock executable, even if
`MPSS_BUILD_WIN32_MOCK_TESTS=ON`; their normal test suite is not a substitute for those mocks.

## Using the MPSS Core Library

### Basic Usage

```cpp
// Standard includes not shown here

#include "mpss/mpss.h"
using namespace mpss;

// Check if an algorithm is supported.
if (!is_algorithm_available(Algorithm::ecdsa_secp256r1_sha256)) {
    // Handle unavailable algorithm.
    // ...
    return;
}

// Create a new key pair. Names must be 1-64 printable ASCII characters.
auto key_pair = KeyPair::Create("my-key", Algorithm::ecdsa_secp256r1_sha256);
if (!key_pair) {
    std::string error = get_error();
    // Handle key creation failure.
    // ...
    return;
}

// Sign some data
std::vector<std::byte> hash = /* your hash data */;
std::vector<std::byte> signature(key_pair->sign_hash_size());
std::size_t sig_len = key_pair->sign_hash(hash, signature);
if (sig_len == 0) {
    std::string error = get_error();
    // Handle signing failure.
    // ...
    return;
}
signature.resize(sig_len);

// Verify the signature.
bool is_valid = key_pair->verify(hash, signature);
```

### Key Management

Names must contain 1-64 printable ASCII characters (`0x20`-`0x7E`). YubiKey additionally
reserves `"(available)"`. `Create`, `Open`, and `Delete` use the default backend unless given
an explicit backend name; `"os"` and `"yubikey"` have separate namespaces.

`Create` refuses existing names. `Open` refuses a name found in multiple storage locations,
such as both Windows KSPs or multiple YubiKey slots. A missing name returns `nullptr` without
an error; ambiguity sets an error. To recognize the same key over time, retain and compare
its public key rather than relying on its name alone.

```cpp
// Open an existing key pair.
auto existing_key = KeyPair::Open("my-key");
if (!existing_key) {
    std::string error = get_error();
    // Key doesn't exist or couldn't be opened.
    // ...
    return;
}

// Extract the public key.
std::vector<std::byte> public_key(existing_key->extract_key_size());
size_t key_len = existing_key->extract_key(public_key);
if (key_len == 0) {
    std::string error = get_error();
    // Handle key extraction failure.
    // ...
    return;
}
public_key.resize(key_len);

// Get key information
KeyInfo info = existing_key->key_info();
Algorithm alg = existing_key->algorithm();
AlgorithmInfo alg_info = existing_key->algorithm_info();

// Delete the key pair when no longer needed.
bool deleted = existing_key->delete_key();
if (!deleted) {
    std::string error = get_error();
    // Handle key deletion failure.
    // ...
    return;
}
```

The member `delete_key()` requires an open handle. Use static `KeyPair::Delete` to clear a
name without opening it, including an ambiguous name:

```cpp
// Clear a name outright, including one that Open refuses as ambiguous.
bool cleared = KeyPair::Delete("my-key");

// Or clear it in a specific backend.
bool cleared_on_yubikey = KeyPair::Delete("my-key", "yubikey");
```

`Delete` targets every matching key **in the selected backend** and obeys YubiKey
[device selection](#device-selection). An absent name in readable storage succeeds.
Invalid input, unavailable storage, or refused authentication fails. Failure can be partial;
do not reuse the name until a later call succeeds.

Windows skips providers it cannot open, so success does not establish absence there.
YubiKey deletion by name requires a valid [slot label](#yubikey-backend-limitations-and-considerations).
After either deletion API succeeds, do not use handles to the deleted keys.

### Key Policies

`KeyPair::Create` accepts an optional [`KeyPolicy`](mpss/key_policy.h), fixed for the key's
lifetime. It contains these packed fields:

| Bits | Field | Backend |
| --- | --- | --- |
| 0-3 | PIN policy | YubiKey |
| 4-7 | Touch policy | YubiKey |
| 8 | User presence | Apple Secure Enclave |
| 9-63 | Reserved | |

Zero leaves a field unset, using environment settings or backend defaults; `KeyPolicy::none`
leaves all fields unset. Creation fails if the backend cannot enforce a requested policy.
Windows and Android accept only `none`.

All policy constants and YubiKey field masks are defined in every build, including the
matching `MPSS_KEY_POLICY_*` C macros. Backend availability still depends on build options.

```cpp
#include "mpss/mpss.h"

// On Apple platforms, require system user authentication whenever this key signs.
auto key = mpss::KeyPair::Create("user-present-key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os",
    mpss::KeyPolicy::apple_secure_enclave_user_presence);

// Fields combine with '|'; unset fields fall back to environment variables and defaults.
auto yk_key = mpss::KeyPair::Create("my-yubikey-key", mpss::Algorithm::ecdsa_secp256r1_sha256, "yubikey",
    mpss::KeyPolicy::yubikey_pin_once | mpss::KeyPolicy::yubikey_touch_cached);
```

Apple user presence requires P-256 and an available Secure Enclave. The OS selects system
authentication, such as Touch ID, Face ID, or passcode; creation does not fall back to software.
For YubiKey settings, see [Key Policy Configuration](#key-policy-configuration).

### Supported Algorithms

The library supports the following ECDSA algorithms:

| Algorithm | Key Size | Security Level | Hash Algorithm | YubiKey PIV Support |
|-----------|----------|----------------|----------------|---------------------|
| `ecdsa_secp256r1_sha256` | 256 bits | 128 bits | SHA-256 | ✓ Yes |
| `ecdsa_secp384r1_sha384` | 384 bits | 192 bits | SHA-384 | ✓ Yes |
| `ecdsa_secp521r1_sha512` | 521 bits | 256 bits | SHA-512 | ✗ No |

**Note**: The YubiKey backend does not support P-521 (secp521r1). Use an OS-native backend for
P-521 where available, but do not assume it will be hardware-backed. Apple Secure Enclave and
Android StrongBox are used only for P-256, and Windows TPM algorithm support varies by device.

### Standalone Verification

You can also verify signatures without a key pair object using the standalone `verify` function:

```cpp
// Verify a signature with a public key.
bool is_valid = mpss::verify(hash, public_key, Algorithm::ecdsa_secp256r1_sha256, signature);
```

### Error Handling

Read `mpss::get_error()` immediately after failure on the same thread.
`mpss::has_error()` checks for an error without allocation and is `noexcept`;
`mpss::clear_error()` marks an error as handled.

#### Last-error contract

Fallible core operations clear the last error on entry; metadata, sizing, and backend-name
accessors leave it untouched. `KeyPair::release_key` is the exception among the fallible ones: it
leaves the last error alone, so that destroying a handle cannot discard what the caller was about
to read. For normal returns:

| Outcome | Return value | Last error |
| --- | --- | --- |
| Success, including recovered fallback | Success value | Empty |
| `Open`: name absent | `nullptr` | Empty |
| `verify`: signature mismatch | `false` | Empty |
| Invalid input, duplicate/ambiguous name, or operational failure | `nullptr`, `false`, or `0` | Diagnostic |

The C API provides `mpss_get_error()`, `mpss_has_error()`, and `mpss_clear_error()`.
The pointer returned by `mpss_get_error()` is valid until that function is called again on
the same thread or the thread exits; copy the string if needed longer.

##### Availability queries

`is_algorithm_available()` returns `false` without an error for an unavailable algorithm;
an unknown algorithm/backend or missing default backend sets an error.
OS backends probe using a scratch key. YubiKey answers from static capabilities, even without
a device. Default-backend queries cache positive results, so availability is not a readiness
or storage-tier guarantee.

##### Internal errors and the OpenSSL error queue

Provider callbacks and fallible C API operations catch C++ exceptions and report
`ERR_LIB_PROV` / `ERR_R_INTERNAL_ERROR` on OpenSSL's error queue, which prints as:

```
error:1C8C0103:Provider routines::internal error
```

Such a failure may leave no MPSS error string. If `mpss_get_error()` itself cannot copy the
string, it returns `"Internal error."`.

Inspect both diagnostics on failure. An absent name makes by-name deletion succeed, so
`false` must not be interpreted as "nothing to delete":

```c
ERR_clear_error();
if (!mpss_delete_key(name)) {
    if (mpss_has_error()) {
        fprintf(stderr, "delete failed: %s\n", mpss_get_error());
    }
    ERR_print_errors_fp(stderr);
}
```

The two channels are independent and thread-local. Clear the OpenSSL queue before an operation
whose errors you want to isolate. A non-empty queue alone does not indicate failure: it may
contain entries from recovered internal steps.

### Thread Safety

A `mpss::KeyPair` handle is safe to use from several threads at once. `sign_hash`, `verify` and
`extract_key` may run concurrently with each other on one handle, while `release_key` and
`delete_key` exclude everything else, so an operation either completes before a release or is
refused by it. Releasing is one decision however many threads ask at once: the backend release runs
exactly once between them, and the rest are told the handle is released.

`KeyPair::Create`, `KeyPair::Open` and `KeyPair::Delete` may be called concurrently, though two of
them naming the same key run one after the other, so that each sees a settled answer rather than
one another half finished. Each handle has its own lock, but that is all it owns: handles
addressing the same key, or the same device, are still coupled through whatever they share.
Deleting a key invalidates every handle to it, and a YubiKey serves one operation at a time
whichever handle asks.

Destroying a handle is not an operation. Like any other object, a `KeyPair` must not be destroyed
while another thread is still inside it.

The last-error channel is per-thread, so concurrent calls do not overwrite each other's
diagnostics. See [Error Handling](#error-handling).

An interaction handler is called on whichever thread performs the operation, and from inside the
locks that operation is holding, so **it must not call back into MPSS**. A call made from a handler
is refused and reports an error rather than being allowed to wait on locks its own caller holds.
See [Custom Interaction Handlers](#custom-interaction-handlers).

**YubiKey.** One device serves one operation at a time. A PIV session is stateful, since verifying
a PIN and then signing are separate exchanges carried on one connection, so MPSS serializes by
device serial across every handle and thread in the process. A key whose touch policy requires a
touch holds the device while it waits, and other threads addressing that device wait with it.
Different YubiKeys proceed in parallel. Listing devices connects to every reader in turn, and
connecting to a device disturbs what a session has established on it, a verified PIN among that, so
a listing runs only while no session is open on any device.

**Other backends.** Apple and Android resolve a key through caches that are internally
synchronized, and Windows hands the key handle the process owns straight to CNG. None of them
serializes by device, so operations on distinct handles proceed in parallel.

### Logging

MPSS logs to `std::cout` and `std::cerr` at `mpss::LogLevel::info` by default.
Use [mpss/log.h](mpss/log.h) to set the minimum level or install a custom logger.
`Logger::Create` accepts arrays of per-level log, flush, and close callbacks; empty callbacks
are ignored. See [stdout_log.cpp](mpss/stdout_log.cpp) for an example.

[mpss/log_c.h](mpss/log_c.h) exposes the same global logger through the `mpss_log_*` C API.
[mpss-openssl/log.h](mpss-openssl/log.h) forwards to it; both APIs share
[one implementation](mpss/log.cpp).

Custom handlers are not automatically flushed or closed at process exit. Call
`mpss::GetLogger()->close()` or `mpss_log_close()` during controlled shutdown.
Closing flushes and removes the handlers; use `ResetDefaultLogger()` or `GetOrSetLogger()`
to resume logging.

## Using MPSS with YubiKey PIV

### Setting Up YubiKey PIV

PIV uses a PIN for user authentication and a management key for key generation and deletion.
Use a non-default PIN and PUK, and retain the PUK for recovery.

For normal use, a **PIN-protected management key** avoids supplying a separate management
secret to MPSS. Complete any [FIPS initialization](#fips-device-readiness) first, then:

```bash
brew install ykman  # macOS
# or: pip install yubikey-manager

ykman piv access change-management-key --generate --protect
```

Alternatively, supply an existing management key:

```bash
export MPSS_YUBIKEY_MGM_KEY='<your management key as 32, 48, or 64 hex characters>'
```

Environment secrets may leak through child processes, diagnostics, or logs. Prefer
PIN-protected management mode and an application-controlled PIN source in production.

Factory-default management-key authentication requires an explicit testing/setup opt-in:

```bash
export MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY=1
```

A malformed or incorrect `MPSS_YUBIKEY_MGM_KEY` never falls back to the factory default.
PIN-derived management keys are unsupported.

### FIPS Device Readiness

Initialize FIPS models according to
[Yubico's device-specific requirements](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-specifics.html)
before generating keys. Check readiness without attempting authentication:

```bash
ykman list
ykman --device <serial> piv info
```

Use the reported PIV `FIPS approved` state, not a default-credential warning, to check the mode.
MPSS adds a FIPS setup hint to generation condition errors, but does not detect or attest FIPS
state; the error can have other causes. MPSS never initializes or resets PIV automatically.

### Runtime Configuration

For unattended use:

```bash
export MPSS_YUBIKEY_PIN='<your actual PIV PIN>'  # Replace the placeholder; do not guess.
```

If the variable is unset or empty, the default handler prompts with echo disabled when needed.
A [custom handler](#custom-interaction-handlers) overrides the environment PIN. MPSS clears its
own PIN buffers, not the original environment value.

Windows and macOS default to `"os"`; Linux defaults to `"yubikey"`. To select YubiKey globally:

```bash
export MPSS_DEFAULT_BACKEND=yubikey
```

Set this before the first backend operation or discovery call. Selection happens once per
process; an unknown or unbuilt backend name leaves no default selected.

### Key Policy Configuration

PIN and touch policies are fixed when a key is created. Set defaults with:

```bash
export MPSS_YUBIKEY_PINPOLICY=once
export MPSS_YUBIKEY_TOUCHPOLICY=cached
```

Unset variables use `once` / `cached`; an explicit `default` delegates to firmware defaults.
`never` permanently disables the corresponding protection for that key. Environment-driven
`never` requires `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1`, otherwise MPSS warns and uses its default.

Explicit [`KeyPolicy` fields](#key-policies) override environment settings and do not require
that opt-in. Unsupported policies still fail creation.

### Custom Interaction Handlers

MPSS requests the PIN, and signals when the device is waiting to be touched, through one interface.
Implement it to replace the built-in terminal prompt with a GUI dialog, a secure-store lookup, or
whatever suits the application.

| Method | Must implement | Called when |
| --- | --- | --- |
| `request_pin` | Yes | MPSS needs a PIN. Return it, or `std::nullopt` to cancel the operation |
| `notify_touch_needed` | Yes | A touch-protected operation is waiting for the user to touch the device |
| `notify_touch_complete` | Yes | That operation finished; `success` is false if the touch timed out |
| `notify_pin_result` | No | After every attempt, and after a request that never reached the device. The only report of success, lockout, or device error |

`request_pin` drives the retry loop. Returning a PIN makes one attempt; if it is wrong, MPSS calls
again with `context.last_status` set to `wrong_pin` and `context.retries_remaining` giving the
device's remaining tries, and the handler decides whether to ask again or give up by returning
`std::nullopt`. Do not return a value the device already refused: MPSS refuses to present it a
second time, because each wrong PIN spends one of the few tries before the device locks.

The two PIN methods report different things, which is why a UI usually needs both. `request_pin`
learns only that a previous attempt was wrong, since it is the request for the *next* attempt;
once the PIN is accepted, or the device locks or errors, MPSS stops calling it. Those outcomes
arrive at `notify_pin_result` instead, so that is where a dialog opened in `request_pin` finds out
to close.

`notify_pin_result` answers every `request_pin` call, so UI opened while answering a request can
always be taken down. When the PIN never reaches the device the result is `not_attempted`: that
covers a handler that cancels, returns an empty PIN, or throws, and a value MPSS withholds because
this device already refused it. No retry is spent in any of those cases. The operation itself also
fails, and the reason is available through its return value and `mpss::get_error()`.

Installing a handler replaces the built-in terminal handler, so `MPSS_YUBIKEY_PIN` is no longer
consulted unless your own implementation chooses to read it.

```cpp
#include "mpss/interaction_handler.h"

class MyInteractionHandler : public mpss::InteractionHandler {
public:
    std::optional<mpss::SecureString> request_pin(const mpss::PinRequestContext &context) override
    {
        if (mpss::PinStatus::wrong_pin == context.last_status &&
            !my_ui::confirm_retry(context.retries_remaining)) {
            return std::nullopt;  // Give up rather than spend another try.
        }

        // context.operation describes what needs the PIN, for the prompt text. Have the dialog
        // return a SecureString so the PIN is never held in an ordinary std::string.
        return my_ui::prompt_for_pin(context.operation);  // std::nullopt if the user cancels.
    }

    void notify_touch_needed() override { my_ui::show_touch_prompt(); }

    void notify_touch_complete(bool success) override { my_ui::hide_touch_prompt(success); }

    // Optional, but it is the only place an outcome other than "wrong PIN" is reported: on success,
    // lockout, a device error, or a PIN that never reached the device, MPSS stops calling request_pin,
    // so a dialog opened there would never learn to close itself. Exactly one result follows every
    // request, so dismissing here is always reached.
    void notify_pin_result(mpss::PinResult result, int retries_remaining) override
    {
        if (mpss::PinResult::not_attempted == result) {
            // MPSS withheld the PIN rather than spend one of the device's few tries on it, or the
            // request was cancelled. No attempt was made, so retries_remaining is unchanged.
            my_ui::hide_pin_dialog();
            return;
        }
        my_ui::report_pin_result(result, retries_remaining);  // ok, wrong_pin, locked, or error.
    }
};

// Install once, before any MPSS operation (typically at application startup).
mpss::GetOrSetInteractionHandler(std::make_shared<MyInteractionHandler>());
```

`notify_touch_needed` and `notify_touch_complete` always come in pairs around the signing call, so
the completion arrives even when no touch was actually required: with a cached touch the device
returns at once and the two land back to back, which shows up as a brief flicker rather than a
prompt the user must act on. A handler that opens a modal dialog should tolerate that, for example
by delaying the dialog briefly and cancelling it if completion has already arrived.

Never log the PIN, and do not keep it after returning it. The handler is called on whichever thread
performs the operation, so an implementation that drives UI must marshal to its own UI thread.

A handler runs from inside the locks the operation is holding, the device's own among them, so it
must not call back into MPSS. Creating, opening, deleting, signing or releasing from a handler is
refused and reports an error, because the alternative is waiting on a lock the handler's own caller
holds, which on a YubiKey means a device that stops answering with someone waiting to touch it. Do
any MPSS work before the operation that needs the PIN, or after it returns.

MPSS stops asking on cancellation, an empty PIN, success, lockout, authentication errors, or
repetition of a PIN this device has already refused.

Callers that cannot subclass a C++ interface can install the same four behaviors as plain function
pointers through [mpss-openssl/interaction_handler.h](mpss-openssl/interaction_handler.h), which
declares `mpss_request_pin_handler_t` and the three notification types.

### Device Selection

MPSS selects the sole detected YubiKey automatically. With multiple devices, select a serial
from `ykman list`:

```bash
export MPSS_YUBIKEY_SERIAL=18268739
```

Creation, opening, and deletion by name obey this selection. Malformed serials are warned
about and treated as unset. Existing `KeyPair` handles retain their serial and slot.
By-name deletion also refuses device enumerations that could not identify an attached device.

Each device has its own PIN, while `MPSS_YUBIKEY_PIN` holds a single value, so a PIN that suits one
device will generally not suit another. Because a device locks after a few wrong PINs and every
operation authenticates afresh, a stale configured PIN would otherwise be spent one retry at a time
until the device locked. MPSS therefore declines to present a PIN that the device has already
refused, and reports that as the reason the operation failed.
The record is kept per serial, so a value one device refused is still offered to another, where it
may well be correct. Only values that device actually refused are withheld, so correcting the PIN
takes effect immediately. MPSS retains a keyed fingerprint of each refused PIN rather than the PIN
itself.
The record lasts for the lifetime of the loaded library. If the device PIN is changed elsewhere to a
value MPSS has already seen refused, restart the process so that value is offered again.

### Summary of Runtime Environment Variables

| Variable | Description | Values | Default |
|----------|-------------|--------|---------|
| `MPSS_DEFAULT_BACKEND` | Default backend, selected at initialization | A name from `get_available_backends()` | `os`; `yubikey` on Linux |
| `MPSS_YUBIKEY_PIN` | PIN used by the default handler | Device-valid PIN | Prompt when needed |
| `MPSS_YUBIKEY_MGM_KEY` | Management key when not using PIN-protected mode | 32, 48, or 64 hex characters | Unset |
| `MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY` | Permit factory-default management-key authentication | `1`, `true`, `yes`, `on` (case-insensitive) | Disabled |
| `MPSS_YUBIKEY_SERIAL` | Device for by-name operations | Positive serial number | Sole detected device |
| `MPSS_YUBIKEY_PINPOLICY` | New-key PIN policy | `default`, `never`, `once`, `always` | `once` |
| `MPSS_YUBIKEY_TOUCHPOLICY` | New-key touch policy | `default`, `never`, `always`, `cached`, `auto` | `cached` |
| `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE` | Permit environment-driven `never` policies | `1`, `true`, `yes`, `on` (case-insensitive) | Disabled |

### YubiKey Backend Limitations and Considerations

| Area | Behavior |
| --- | --- |
| Capacity | 20 [retired PIV slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html); delete keys to free space |
| Algorithms | P-256 and P-384; no P-521 |
| Device access | Key operations require the device, including verification through a `KeyPair`. Standalone verification with an extracted public key does not |
| Authentication | Creation/deletion request a PIN only after authentication-related failure; other refusals do not trigger a PIN retry |
| PIN lockout | A PIN the device refuses is not presented to it again for the lifetime of the process, so a stale `MPSS_YUBIKEY_PIN` cannot spend the device's remaining retries. Recorded per serial, so other devices are unaffected |
| PIN policy | MPSS reconnects per operation, so `once` need not cache the PIN across signing calls. `never` affects signing, not management authentication |
| Touch policy | `cached` needs a touch only if more than 15 seconds have passed since the last one. The handler is notified whenever the policy is not `never`, so under `cached` a prompt can appear when the cached touch means none is actually required. MPSS sets no timeout of its own; signing blocks until the device gives up, and an untouched key fails the operation |
| Concurrency | Run one PIV writer per device. Multi-step operations are not atomic across processes |

Names live in each slot's label certificate, whose public key must match the slot key.
MPSS ignores mismatched labels and refuses ambiguous names. Labels are not attestations;
a writer with management credentials can replace both key and label. Storing an unrelated
certificate in the slot replaces MPSS's label.

By-name deletion clears keys with matching labels on the selected device and fails if a slot is unreadable.
Keys without valid labels require direct slot administration. Existing handles retain a serial
and slot, not an immutable key snapshot.

Firmware 5.7 and later supports key erasure. On firmware without that command, MPSS overwrites
the key with a dummy and labels the slot `"(available)"` for reuse; this is not evidence of
physical zeroization. Such a slot appears in `ykman piv info` as:

```
Slot 82 (RETIRED1):
  Private key type: ECCP256
  Public key type:  ECCP256
  Subject DN:       CN=(available),OU=mpss,O=Microsoft
  Issuer DN:        CN=mpss slot label (not an issuer),O=Microsoft
```

Failure to remove or update a label after successful key deletion logs a warning and may require
manual slot cleanup.

### Running Tests with a YubiKey

> **Use a dedicated test YubiKey and disconnect non-test devices.** Tests create and delete
> keys, even when `"os"` is the default backend. Confirm the device and retry counters with
> `ykman piv info`. Stop after a wrong PIN: exhausting retries locks it, requiring the PUK.
> A PIV reset destroys all PIV keys and certificates.

To run the tests with the YubiKey backend and interactive PIN input:

```bash
MPSS_DEFAULT_BACKEND=yubikey out/build/macos-arm64-with-yubikey-debug/bin/mpss_tests
```

For unattended runs, supply the known PIN through the handler or `MPSS_YUBIKEY_PIN`.
Disabling touch on test keys requires both `MPSS_YUBIKEY_TOUCHPOLICY=never` and
`MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1`.

P-521, multi-device, and factory-default-management-key cases skip when their requirements
are unmet. Selecting `"yubikey"` without a device causes ordinary key-operation tests to fail.
The slot-binding test requires directly available management credentials; its raw PIV calls
do not perform the public API's PIN-protected-management-key retry.

## OpenSSL Provider (mpss-openssl)

Load the provider to create keys, open `mpss:` URIs, or read key-reference PEM files through
OpenSSL. Key protection is determined by the selected backend.

### Provider Components

| Interface | Purpose |
| --- | --- |
| [api.h](mpss-openssl/api.h) | Provider initialization, policy constants, discovery, errors, and by-name deletion |
| [interaction_handler.h](mpss-openssl/interaction_handler.h) | C callbacks for YubiKey PIN entry and touch notifications |
| [log.h](mpss-openssl/log.h) | The shared C logging API |
| [provider/](mpss-openssl/provider/) | Key management, signing, digests, codecs, and store implementation |

### Using the OpenSSL Provider

These usage fragments omit some error handling; check OpenSSL return values and release
resources on all paths. Register a statically linked provider with `OSSL_PROVIDER_add_builtin`.
For dynamic loading, make its shared library available on OpenSSL's provider search path.

#### 1. Basic Key Generation and Signing

```cpp
#include "mpss-openssl/api.h"
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
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
char my_key_name[] = "my-openssl-key";
char algorithm[] = "ecdsa_secp256r1_sha256";
OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string("mpss_key_name", my_key_name, 0),
    OSSL_PARAM_construct_utf8_string("mpss_algorithm", algorithm, 0),
    // Optional: mpss_backend and mpss_key_policy (see parameter table below).
    OSSL_PARAM_END};
EVP_PKEY_CTX_set_params(ctx, params);

EVP_PKEY *pkey = nullptr;
EVP_PKEY_generate(ctx, &pkey);
if (!pkey) {
    // Read MPSS diagnostics and OpenSSL's queue before making another fallible call.
    const char *error_msg = mpss_get_error();
    fprintf(stderr, "Error: %s\n", error_msg);
    ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(mpss_prov);
    OSSL_PROVIDER_unload(default_prov);
    OSSL_LIB_CTX_free(libctx);
    return;
}
EVP_PKEY_CTX_free(ctx);

// Sign data using standard OpenSSL operations
EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=mpss");
EVP_PKEY_sign_init(sign_ctx);
// ... perform signing operations
EVP_PKEY_CTX_free(sign_ctx);

// Close the key but note that it is not deleted
EVP_PKEY_free(pkey);

// Keep these alive until all keys and operation contexts using them have been freed.
OSSL_PROVIDER_unload(mpss_prov);
OSSL_PROVIDER_unload(default_prov);
OSSL_LIB_CTX_free(libctx);
```

#### 2. Opening Existing Keys and Public Key Extraction

Open `mpss:<key_name>` through `OSSL_STORE` with **`"provider=mpss"`** to select MPSS key
management. Supply `mpss_backend` to select a non-default backend. The result is an `EVP_PKEY`
referencing the stored key; ambiguous names are refused.

The remaining examples assume a live `libctx` with MPSS and the default provider loaded.

```cpp
#include <openssl/store.h>
#include <openssl/pem.h>

// Open an existing MPSS key by name.
OSSL_STORE_CTX *store =
    OSSL_STORE_open_ex("mpss:my-openssl-key", libctx, "provider=mpss", nullptr, nullptr, nullptr, nullptr, nullptr);
if (store == nullptr) {
    // Report the open failure.
    return;
}

// An MPSS store yields at most one key.
EVP_PKEY *existing_pkey = nullptr;
OSSL_STORE_INFO *info = OSSL_STORE_load(store);
if (info != nullptr) {
    if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
        existing_pkey = OSSL_STORE_INFO_get1_PKEY(info);
    }
    OSSL_STORE_INFO_free(info);
}
OSSL_STORE_close(store);
if (existing_pkey == nullptr) {
    // Report the key-load failure.
    return;
}

// Extract the public key (SPKI) in PEM format.
BIO *pk_file = BIO_new_file("pk.pem", "w");
PEM_write_bio_PUBKEY_ex(pk_file, existing_pkey, libctx, "provider=mpss");
BIO_free(pk_file);

// ... use existing_pkey, then free it.
EVP_PKEY_free(existing_pkey);
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
X509_free(cert);
```

#### 4. Provider-Specific Parameters

**Settable parameters** (passed via `EVP_PKEY_CTX_set_params` during key generation):

| Parameter | Type | Required | Description |
|---|---|---|---|
| `mpss_key_name` | UTF-8 string | Yes | A persistent name, unique within the selected backend, containing 1-64 printable ASCII characters. The YubiKey backend reserves `"(available)"`. |
| `mpss_algorithm` | UTF-8 string | Yes | Algorithm suite, e.g., `"ecdsa_secp256r1_sha256"` |
| `mpss_backend` | UTF-8 string | No | Backend name; defaults to the selected backend. List names with `mpss_get_available_backends()` |
| `mpss_key_policy` | uint64 | No | `MPSS_KEY_POLICY_*` fields from `api.h`; defaults to `NONE`. The backend must enforce the requested policy |

**Gettable parameters** (queried via `EVP_PKEY_get_params` on an existing key):

| Parameter | Type | Description |
|---|---|---|
| `mpss_key_name` | UTF-8 string | The key's persistent name. |
| `mpss_algorithm` | UTF-8 string | The key's algorithm suite (canonical form). |
| `mpss_backend` | UTF-8 string | The backend that created or opened the key. |
| `is_hardware_backed` | int | The core `KeyInfo` boolean, exposed as `1` or `0`. Windows reports `1` for both TPM and VBS keys; this is not a TPM-storage guarantee. |
| `storage_description` | UTF-8 string | Human-readable description of the storage location (e.g., `"Keychain"`, `"YubiKey PIV"`). |

The standard OpenSSL parameters `OSSL_PKEY_PARAM_BITS`, `OSSL_PKEY_PARAM_SECURITY_BITS`, `OSSL_PKEY_PARAM_MANDATORY_DIGEST`, and `OSSL_PKEY_PARAM_DEFAULT_DIGEST` are also supported.

#### 5. Certificate Authority and Certificate Chain Creation

A complete end-to-end example of creating a CA certificate with an MPSS-backed key and signing end-entity certificates with it is shown in [tests/mpss_openssl_e2e_test.cpp](tests/mpss_openssl_e2e_test.cpp).

#### 6. Secure Key Cleanup

Both deletion entry points call `mpss::KeyPair::Delete`, with its
[backend scope and partial-failure rules](#key-management). An absent name in readable storage
succeeds; ambiguous names can be cleared without opening a handle.

**Through OpenSSL:**

```cpp
// Returns 1 if the name is clear, including an absent name; 0 on failure.
int deleted = OSSL_STORE_delete("mpss:my-old-key", libctx, "provider=mpss", nullptr, nullptr, nullptr);

// To delete from a specific backend, pass an mpss_backend parameter:
char backend_name[] = "yubikey";
OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("mpss_backend", backend_name, 0), OSSL_PARAM_END};
OSSL_STORE_delete("mpss:my-old-key", libctx, "provider=mpss", nullptr, nullptr, params);
```

**Through the C API**, without loading a provider or creating an OpenSSL context:

```cpp
#include "mpss-openssl/api.h"

bool cleared = mpss_delete_key("my-old-key");
// Or: mpss_delete_key_from_backend("my-old-key", "yubikey");
```

Do not use handles to deleted keys. Freeing an `EVP_PKEY` alone does not delete the stored key.
Deletion is irreversible but does not prevent verification of existing signatures or certificates.
MPSS does not provide key-name enumeration.

#### 7. Loading a Key from a Key Reference PEM

For applications that load keys from files, use a **key reference PEM**. It contains a
backend and key name, not private key material:

```
-----BEGIN MPSS KEY REFERENCE-----
b3MAbXkta2V5
-----END MPSS KEY REFERENCE-----
```

The body is base64-encoded `<backend>\0<key_name>` (`os\0my-key` above).

**Writing a reference.** The reference is produced through the standard encoder API, selecting the
`MpssKeyReference` output structure:

```cpp
#include <openssl/encoder.h>

// key is an EVP_PKEY previously created or opened through the MPSS provider.
OSSL_ENCODER_CTX *ectx =
    OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_PRIVATE_KEY, "PEM", "MpssKeyReference", "provider=mpss");
BIO *out = BIO_new_file("my-key.pem", "w");
OSSL_ENCODER_to_bio(ectx, out);
BIO_free(out);
OSSL_ENCODER_CTX_free(ectx);
```

**Reading a reference.** Load the MPSS provider, then use the standard PEM reader.
Unlike `OSSL_STORE`, no property query is needed:

```cpp
BIO *in = BIO_new_file("my-key.pem", "r");
EVP_PKEY *key = PEM_read_bio_PrivateKey_ex(in, nullptr, nullptr, nullptr, libctx, nullptr);
BIO_free(in);
if (key == nullptr) {
    // Report the decode/reopen failure before using the key.
    return;
}

// ... use key, then free it.
EVP_PKEY_free(key);
```

`PEM_write_bio_PrivateKey` requests private material and fails; use the reference encoder above.

A reference resolves the name again in its recorded backend, using current device-selection
rules. It contains no fingerprint or device serial: replacing the file or reusing the key name
can select a different key. Protect reference files as credential-selection configuration.
Reading fails if the name is absent, ambiguous, or inaccessible.

### Building mpss-openssl

Set `MPSS_BUILD_MPSS_OPENSSL_STATIC=ON` or `MPSS_BUILD_MPSS_OPENSSL_SHARED=ON`.
For iOS packaging, see [iOS](#ios).

### Examples and Testing

See [provider tests](tests/mpss_openssl_tests.cpp) and
[certificate-chain examples](tests/mpss_openssl_e2e_test.cpp). They are built with
`MPSS_BUILD_TESTS=ON` when the provider is enabled.

## Contributing to MPSS

MPSS is released under the MIT license. Contributions are welcome;
[submit an issue](https://github.com/microsoft/mpss/issues) for questions, bugs, or feature requests.
