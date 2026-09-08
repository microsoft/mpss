# MPSS - A Multi-Platform Secure Signing Library

Modern operating systems provide various methods for safeguarding private cryptographic keys through hardware.
MPSS is a multi-platform C++ library for generating and storing (secret) digital signature keys.
It offers a unified API so that downstream applications do not need to worry about the specific APIs used by different operating systems.

In addition to the core library, MPSS includes an OpenSSL 3.x provider, which enables MPSS to be used easily through the OpenSSL API.

MPSS uses the following technologies on the different supported platforms:

| Platform | API |
|----------|-----|
| Windows | TPM-backed [MS_PLATFORM_KEY_STORAGE_PROVIDER](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider) if available; [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) otherwise; software-protected storage if neither |
| macOS / iOS | [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave) if available; [Keychain](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain) otherwise |
| Android | [StrongBox](https://developer.android.com/privacy-and-security/keystore) if available; [Trusted Execution Environment](https://source.android.com/docs/security/features/trusty) otherwise |
| Linux | [YubiKey PIV](https://developers.yubico.com/PIV/) (default, see below) |
| YubiKey (optional) | [YubiKey PIV](https://developers.yubico.com/PIV/) (cross-platform: Windows, macOS, Linux only) |

**Note**: The YubiKey PIV backend is an optional cross-platform backend for **desktop platforms** (Windows, macOS, Linux) that can be enabled by setting `MPSS_BACKEND_YUBIKEY=ON` during CMake configuration. On Linux, it serves as the only available backend. The YubiKey backend is **not supported on iOS or Android**.

**Note**: On Windows the three options above are tried in order and the first that succeeds is
used, so the tier is a property of each key rather than of the machine. A TPM that does not
implement a requested algorithm, for example, yields a VBS key on the very host where another
algorithm yields a TPM key. Creation reports success and sets no error in all three cases, so read
`key_info().is_hardware_backed` and `key_info().storage_description` (`"TPM Protection"`,
`"Virtualization Based Security"`, or `"Software Protection"`) to find out what a key actually got.
Only the last of the three is outside hardware.

## Compiling for different platforms

MPSS core depends only on operating system APIs, except that it uses [GoogleTest](https://GitHub.com/Google/GoogleTest) for testing.
When the YubiKey backend is enabled, it additionally depends on [libykpiv](https://developers.yubico.com/yubico-piv-tool/) and [OpenSSL](https://GitHub.com/openssl/openssl), both provided automatically by vcpkg.
The OpenSSL provider naturally requires [OpenSSL](https://GitHub.com/openssl/openssl) as well.

A [vcpkg port](ports/mpss/) is provided for **desktop platforms only** (Windows, macOS, Linux). On these platforms, downstream projects can consume MPSS as a vcpkg package once the port is published to a registry. **iOS and Android are not covered by the vcpkg port** — on those platforms, build MPSS directly from source using the dedicated paths described in the platform-specific sections below (the iOS XCFramework helper for iOS, and the direct NDK-based CMake build for Android). Note that even on iOS and Android, vcpkg may still be used as the *dependency manager* (for example, to fetch OpenSSL) — that is independent of the port.

### Using CMake Presets

MPSS provides [CMake presets](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html)
for desktop builds, Android builds, and Apple Silicon iOS Simulator testing.
Ensure [vcpkg](https://GitHub.com/Microsoft/vcpkg) is installed and the environment variable `VCPKG_ROOT` is set, then run:

```bash
cmake -S . --preset <configure-preset-name>
cmake --build --preset <build-preset-name>
cmake --install out/build/<configure-preset-name> # optional; to install in custom destination, include --prefix <destination>
```

The list of available presets can be seen by running `cmake --list-presets=all`.
Presets whose name includes `-with-yubikey` additionally enable the YubiKey PIV backend ([see prerequisites below](#prerequisites)).
Presets whose name includes `-shared` build MPSS (and the OpenSSL provider) as shared libraries; otherwise the default is static.
Linux presets build for the native host architecture. Architecture-specific Windows and macOS presets
select that output architecture explicitly; Android and iOS presets target their named platform
architecture independently of the host.

If you do not want to use presets, you can configure manually as shown in the platform-specific sections below.

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

### Linux / YubiKey Backend

The YubiKey PIV backend provides hardware-backed key storage using a YubiKey USB security key. It is supported on **desktop platforms only** (Windows, macOS, Linux).

#### Prerequisites

The YubiKey backend requires a YubiKey 4 or 5 series device. The required `libykpiv` library (from [yubico-piv-tool](https://github.com/Yubico/yubico-piv-tool)) is provided automatically by vcpkg — no manual installation is needed.

On **Linux**, the PC/SC smart card library must be installed separately, as it is a system dependency:

```bash
# Debian/Ubuntu
sudo apt install libpcsclite-dev

# Fedora/RHEL
sudo dnf install pcsc-lite-devel
```

#### Build Configuration

- **Linux:**
  ```bash
  cmake --preset linux-with-yubikey-release
  cmake --build --preset linux-with-yubikey-release
  ```

  The Linux presets build for the host's native architecture. They do not provide cross-compilation
  toolchains.

- **macOS:**
  ```bash
  cmake --preset macos-arm64-with-yubikey-release
  cmake --build --preset macos-arm64-with-yubikey-release
  ```

  Use the corresponding `macos-x64-...` preset when targeting x64. The macOS presets
  target macOS 13.3 or later and apply the selected architecture to both C-family and
  Swift compilation.

- **Windows:**
  ```cmd
  cmake --preset win-vs2022-x64-with-yubikey
  cmake --build --preset win-vs2022-x64-with-yubikey-release
  ```

On Linux, the YubiKey backend will be used as the default since Linux has no OS-native backend.
On Windows and macOS, the OS-native backend remains the default unless you set an environment variable `MPSS_DEFAULT_BACKEND=yubikey` at runtime.
In [Using MPSS with YubiKey PIV](#using-mpss-with-yubikey-piv) we explain how to use MPSS with YubiKey PIV, as it is a little complicated.

### iOS

The easiest way to build XCFrameworks for iOS is with the provided CMake script:

```bash
# Core library + OpenSSL provider (default):
cmake -P cmake/ios_xcframework.cmake

# Core library only (without OpenSSL provider):
cmake -DBUILD_MPSS_OPENSSL=OFF -P cmake/ios_xcframework.cmake

# Debug build, custom output directory:
cmake -DBUILD_TYPE=Debug -DOUTPUT_DIR=./out -P cmake/ios_xcframework.cmake
```

This configures and builds for both device (`iphoneos`) and simulator (`iphonesimulator`), installs both, and creates the XCFramework bundle(s) automatically.
The output is placed in the project root by default (`libmpss.xcframework` and `libmpss-openssl.xcframework`).
The XCFrameworks target **iOS only**: arm64 slices for the device (`iphoneos`) and the Apple Silicon iOS simulator (`iphonesimulator`).

For other Apple platforms, build directly with the appropriate `CMAKE_SYSTEM_NAME` / `CMAKE_OSX_SYSROOT` / `CMAKE_OSX_ARCHITECTURES` and bundle the resulting `.a` files into your own XCFramework.

Once you have the XCFramework(s), you can simply include them in your Xcode project as Framework dependencies.
You will naturally still need to build OpenSSL itself for iOS to be able to load and use the OpenSSL provider.

Note that the MPSS core API is C++ and is intended to be consumed from C++ or Objective-C++.
Swift consumers should either wrap the parts they need in a thin Objective-C facade, or interact with MPSS-backed keys through the OpenSSL provider's standard `EVP_*` C API.

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

The iOS tests run in a hosted XCTest bundle inside a minimal UIKit application. This is required
because Keychain behavior depends on an application runtime, entitlements, and bundle identity.
The simulator path deliberately reports Secure Enclave as unavailable, so it validates the
Keychain-backed fallback without making hardware-security claims.

Run the complete native core and OpenSSL test suite with:

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

The preset targets Apple Silicon Macs, uses the iOS 16.3 deployment target, and builds the static
core and OpenSSL provider with the complete test suite. Override a setting after the preset name
when investigating another supported configuration. The XCTest bridge fails on GoogleTest failures
or if no native tests are discovered.

#### Running on a physical iOS device

Physical-device testing is the only valid way to exercise the Secure Enclave backend. Configure
the project with the Xcode generator and the device SDK, then select your development team and
provisioning profile in Xcode:

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

The Simulator suite does not validate Secure Enclave behavior. Record the device
model, iOS version, signing team, and test result when making hardware-backed security claims.

### Android

The `android-base` preset is the source of truth for the Android compile API, Build Tools, and NDK
versions. It pins the minimum API to 28 and uses JDK 21 to emit Java 17 bytecode. The Android presets
build shared MPSS libraries with `libc++_shared.so`, select the matching vcpkg triplet, and derive
`ANDROID_NDK_HOME` from `ANDROID_HOME`. Set `ANDROID_HOME`, `JAVA_HOME`, and `VCPKG_ROOT`.

Configure and build for x86_64 Android:

```bash
cmake --preset android-x64-release
cmake --build --preset android-x64-release

cmake --install out/build/android-x64-release --prefix out/install/android-x64-release
```

Configure and build for arm64 Android:

```bash
cmake --preset android-arm64-release
cmake --build --preset android-arm64-release

cmake --install out/build/android-arm64-release --prefix out/install/android-arm64-release
```

The Debug variants are `android-x64-debug` and `android-arm64-debug`.

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

This is an explicit, idempotent workstation-setup command; normal configure and build commands do
not run it. Run it after installing the Android command-line tools and whenever `android-base`
changes. The Android CI pipeline invokes the same helper before configuring either Android preset.

`CMAKE_SYSTEM_VERSION` sets the minimum Android API level for the native library. MPSS supports
API level 28 and later. `MPSS_ANDROID_COMPILE_API` selects the Android platform used to compile the
Java sources and does not raise the runtime minimum. The installer reads its value directly from the
preset rather than duplicating it here.

P-256 key creation first requests StrongBox and falls back to AndroidKeyStore when StrongBox is
unavailable. Before API level 31, hardware-backed storage is reported as `Unknown Secure`; API
level 31 and later report the specific Android security level.

API level 28 is a compatibility floor, not a security-maintenance guarantee. Applications using
MPSS should require devices that receive current security updates and have a current Android
security patch level.

The Android presets enable the shared OpenSSL provider and the test suite. Pass
`-DMPSS_BUILD_MPSS_OPENSSL_SHARED=OFF` or `-DMPSS_BUILD_TESTS=OFF` after the preset name for a
smaller library-only build.

All Android MPSS builds use `libc++_shared.so`. MPSS exposes a C++ API from a shared library, so a
native application linking to MPSS must use the same C++ runtime for objects, allocations, and
exceptions that cross the shared-library boundary. Using a statically linked libc++ in either
library would put two C++ runtimes in one process.

When MPSS is the top-level CMake project, it selects `c++_shared` automatically and installs the
matching `libc++_shared.so` beside the MPSS libraries. When MPSS is used through `add_subdirectory()`
or `find_package()`, the consuming project must select the shared runtime before CMake enables C++.
For an Android Gradle module using `externalNativeBuild`, pass the selection to CMake:

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

Configure the consuming Gradle project to use the NDK version selected by `android-base`. For
CMake's native Android toolchain, configure the parent project with
`-DCMAKE_ANDROID_STL_TYPE=c++_shared` instead.

The native target can then link to the exported MPSS target normally:

```cmake
find_package(mpss CONFIG REQUIRED)

add_library(app_native SHARED app_native.cpp)
target_link_libraries(app_native PRIVATE mpss::mpss)
```

MPSS rejects Android dependency builds configured with another C++ runtime rather than allowing an
unsafe mixed-runtime process. Use the same NDK version for MPSS, the consuming native library, and
the packaged `libc++_shared.so`. The APK must contain one `libc++_shared.so` for each packaged ABI,
alongside every native library that needs it. The Java classes from `mpss.jar` are packaged
separately as a Gradle dependency and do not replace the native C++ runtime. Gradle packages the
selected shared runtime for an `externalNativeBuild`; do not also add a second copy through
`jniLibs`.

Packaging the native library does not initialize its Java bridge. Before calling MPSS from native
code, load MPSS explicitly from Java or Kotlin so Android runs `JNI_OnLoad` with the application's
class loader:

```java
static
{
    System.loadLibrary("mpss");
    System.loadLibrary("app_native");
}
```

Load `mpss` before a native application library that links to it. Initialization resolves the Java
classes supplied by `mpss.jar`; if the JAR or native library is missing, the load fails immediately
instead of leaving a partially initialized backend. Loading `libmpss.so` only as an ELF dependency
or through native `dlopen` is not a substitute for `System.loadLibrary("mpss")`.
The argument is the packaged filename without its `lib` prefix or `.so` suffix; use `mpss_debug`
when packaging MPSS's default Debug output.

#### Running the Android tests

Android tests run inside a headless instrumentation APK so they have an ART runtime, an application
UID and AndroidKeyStore namespace, and the Java class-loader environment required by the JNI
backend. The Android presets enable `MPSS_BUILD_TESTS`; their default build compiles the C++ tests as
`libmpss_tests.so`, packages the Java and native components, and creates:

```text
<build-directory>/android-tests/mpss-tests.apk
```

For a typical arm64 physical device, configure and build the Debug test APK with:

```bash
cmake --preset android-arm64-debug
cmake --build --preset android-arm64-debug
```

This creates `out/build/android-arm64-debug/android-tests/mpss-tests.apk`. Use the
`android-x64-debug` preset and matching build directory for an x86_64 emulator.

The test build automatically uses and packages `libc++_shared.so`; no separate C++ runtime setup is
required. The checked-in Gradle wrapper supplies the required Gradle version, so a global Gradle
installation is also unnecessary. CMake passes its normalized minimum API and
`MPSS_ANDROID_COMPILE_API` values to Gradle, which uses them as the APK's `minSdk` and
compile/target SDK respectively.

For a physical device, enable Developer options and USB debugging, connect the device, and accept
the computer authorization prompt on the device. Confirm that Android Debug Bridge lists it with
the `device` status rather than `unauthorized`:

```bash
adb devices
adb shell getprop ro.product.cpu.abi
```

The reported ABI must match the CMake build; most current physical devices report `arm64-v8a` and
use the `android-arm64-debug` preset. The device must run Android API level 28 or later. Start a
matching emulator or connect an authorized physical device, then install and run the APK:

```bash
adb install -r out/build/android-arm64-debug/android-tests/mpss-tests.apk
adb logcat -c
adb shell am instrument -w com.microsoft.research.mpss.tests/.TestRunner
adb logcat -d -s MPSS:V MPSS_TESTS:V '*:S'
```

Unlike an Apple bundle identifier, the Android application ID is not claimed through a central
developer account. The test APK is signed with Gradle's local debug key, so it can run unchanged on
a physical device. If another APK with the same application ID but a different signing key is
already installed, remove it with `adb uninstall com.microsoft.research.mpss.tests` before
installing this APK.

`MPSS` contains library trace and error messages; `MPSS_TESTS` contains GoogleTest events and the
final pass, skip, and failure counts.

An emulator validates the Android runtime, JNI, AndroidKeyStore integration, signing, verification,
and key-management behavior, but it does not establish hardware-backed security. Verify TEE and
StrongBox behavior separately on suitable physical devices.

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

If the module does not use `externalNativeBuild`, also copy `libc++_shared.so` from the same MPSS
installation beside `libmpss.so`. If the module builds any native target with
`externalNativeBuild`, do not put another `libc++_shared.so` in `jniLibs`; configure that native
build for `c++_shared` as shown above and let Gradle package its runtime.

**Note**: Only shared libraries are supported on Android. Static builds will produce a configuration error.

### Common Build Options

The following table outlines the common CMake configuration options recognized by the build system:

| Option | Description |
|--------|-------------|
| `MPSS_BUILD_TESTS=ON` | Build the test suite. |
| `MPSS_BUILD_MPSS_CORE_STATIC=ON` | Build the core library as a static library. |
| `MPSS_BUILD_MPSS_CORE_SHARED=ON` | Build the core library as a shared library. |
| `MPSS_BUILD_MPSS_OPENSSL_STATIC=ON` | Build the OpenSSL provider as a static library. |
| `MPSS_BUILD_MPSS_OPENSSL_SHARED=ON` | Build the OpenSSL provider as a shared library. |
| `MPSS_BACKEND_YUBIKEY=ON` | Enable the YubiKey PIV backend. |
| `MPSS_ENABLE_HARDENING=OFF` | Disable security hardening compile and link flags (default is `ON`). |
| `BUILD_SHARED_LIBS=ON` | Build all targets as shared libraries (convenience shortcut). |

Static targets are named `mpss::mpss_static` and `mpss::mpss_openssl_static`, whereas shared targets are `mpss::mpss` and `mpss::mpss_openssl`.
As usual, you can set `CMAKE_BUILD_TYPE` to set the build type (`Release`, `Debug`, etc.) when using a single-configuration generator.

## Using the MPSS Core Library

The MPSS core library provides a simple C++ API for creating, managing, and using cryptographic key pairs in secure storage. Here's how to get started:

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

// Create a new key pair. Key names must not exceed 64 characters.
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

After `delete_key()` succeeds, all `KeyPair` objects referring to that key must be considered invalid
and must not be used. Their subsequent behavior is backend-dependent and is not part of the MPSS API
contract.

`delete_key()` needs an open key pair, so it can only remove a key that `Open` was able to resolve.
When a name is held by more than one key — which `Open` refuses rather than guessing between — there
is no key pair to call it on. `KeyPair::Delete` clears the name instead, without opening anything:

```cpp
// Clear a name outright, including one that Open refuses as ambiguous.
bool cleared = KeyPair::Delete("my-key");

// Or clear it in a specific backend.
bool cleared_on_yubikey = KeyPair::Delete("my-key", "yubikey");
```

Every key stored under the name is removed, not just the one an open would have resolved to: leaving
one behind would let the name start resolving again, to whichever copy happened to survive. Clearing
a name that holds nothing **succeeds** — the call asks that the name hold no key, and it already
does, so reporting failure would describe the starting state rather than the outcome. A `false`
return means a key could not be removed or the storage could not be read. Because clearing continues
past a source it could not clear, such a failure may be partial, so treat the name as unsafe to
reuse until a later call succeeds.

### Key Policies

`KeyPair::Create` takes an optional [`KeyPolicy`](mpss/key_policy.h) that constrains how the key may
later be used. A policy is baked into the key when it is created and cannot be changed afterwards;
keys that already exist are unaffected by policies chosen later.

`KeyPolicy` is a bitmask of packed fields, one per policy aspect:

| Bits | Field | Backend |
| --- | --- | --- |
| 0-3 | PIN policy | YubiKey |
| 4-7 | Touch policy | YubiKey |
| 8 | User presence | Apple Secure Enclave |
| 9-63 | Reserved | |

Within a field, zero means "unset": the backend falls back to its environment variable, if it has
one, and otherwise to its own default. `KeyPolicy::none` leaves every field unset and so preserves
default behavior.

**A backend rejects any non-zero policy field it cannot enforce, and creation fails.** This is
deliberate. A policy is a security requirement, so failing is better than returning a key that
silently does not honor it.

```cpp
#include "mpss/key_policy.h"

// Require system user authentication whenever this key signs.
auto key = mpss::KeyPair::Create("user-present-key", mpss::Algorithm::ecdsa_secp256r1_sha256, "os",
    mpss::KeyPolicy::apple_secure_enclave_user_presence);

// Fields combine with '|'; unset fields fall back to environment variables and defaults.
auto yk_key = mpss::KeyPair::Create("my-key", mpss::Algorithm::ecdsa_secp256r1_sha256,
    mpss::KeyPolicy::yubikey_pin_once | mpss::KeyPolicy::yubikey_touch_cached);

// No policy: every field falls back to environment variables and defaults.
auto default_key = mpss::KeyPair::Create("my-key2", mpss::Algorithm::ecdsa_secp256r1_sha256);
```

The YubiKey enumerators are compiled only when the YubiKey backend is enabled
(`MPSS_BACKEND_YUBIKEY`).

**Apple Secure Enclave user presence.** `KeyPolicy::apple_secure_enclave_user_presence` requires
system user authentication when the key signs. It is enforced by the Secure Enclave access control
attached when the key is created, and the operating system chooses an available authentication
mechanism, such as Touch ID, Face ID, or the device passcode. Creation fails rather than silently
using a software key if the requested algorithm or an available Secure Enclave cannot satisfy the
policy.

**YubiKey PIN and touch policies** can also be set through environment variables, and interact with
several device-specific considerations. See
[Key Policy Configuration](#key-policy-configuration) in the YubiKey chapter.

### Supported Algorithms

The library supports the following ECDSA algorithms:

| Algorithm | Key Size | Security Level | Hash Algorithm | YubiKey PIV Support |
|-----------|----------|----------------|----------------|---------------------|
| `ecdsa_secp256r1_sha256` | 256 bits | 128 bits | SHA-256 | ✓ Yes |
| `ecdsa_secp384r1_sha384` | 384 bits | 192 bits | SHA-384 | ✓ Yes |
| `ecdsa_secp521r1_sha512` | 521 bits | 256 bits | SHA-512 | ✗ No* |

**Note**: YubiKey PIV does not support P-521 (secp521r1). If you need P-521 support, use an OS-native backend.

### Standalone Verification

You can also verify signatures without a key pair object using the standalone `verify` function:

```cpp
// Verify a signature with a public key.
bool is_valid = mpss::verify(hash, public_key, Algorithm::ecdsa_secp256r1_sha256, signature);
```

### Error Handling

Use the `mpss::get_error()` function to retrieve detailed error information when operations fail:
```cpp
auto key_pair = KeyPair::Create("duplicate-name", Algorithm::ecdsa_secp256r1_sha256);
if (!key_pair) {
    std::string error_msg = mpss::get_error();
    std::cerr << "Key creation failed: " << error_msg << std::endl;
}
```

Two companion functions round out the error surface. `mpss::has_error()` reports whether an error is
set without building a string, so unlike `mpss::get_error()` it allocates nothing and is `noexcept` —
safe to call from a `noexcept` context or after an allocation failure. `mpss::clear_error()` resets
the last error for the calling thread.

```cpp
if (mpss::has_error()) {
    std::cerr << "Key creation failed: " << mpss::get_error() << std::endl;
    mpss::clear_error();
}
```

Every fallible operation already clears the last error on entry (rule 1 below), so `clear_error()` is
never needed to keep one call's error from leaking into the next. It is for callers that have
consumed an error and want a clean slate before running their own logic, or before a sequence of
accessors, which deliberately leave the last error untouched. There is deliberately no public way to
*set* the last error: only MPSS itself can produce a diagnostic.

#### Last-error contract

Every backend (Windows, Apple, Android, and YubiKey) honors the same last-error contract, so
`mpss::get_error()` behaves identically regardless of which backend is active:

1. **Cleared on entry.** Each public operation that can fail clears the last-error string before it
   does any work. After such a call returns, `mpss::get_error()` reflects *only* that call — never a
   stale message left over from an earlier operation on the same thread. Accessors that cannot fail
   (`algorithm()`, `key_info()`, `sign_hash_size()`, `extract_key_size()`, `release_key()`,
   `get_error()`, `has_error()`, `get_available_backends()`, `get_default_backend_name()`) leave the
   last error untouched, so a diagnostic remains readable while the caller prepares to report it —
   including while naming the backend it came from.
2. **Set on operational failure.** A descriptive message is set whenever an operation cannot be
   carried out: empty or malformed input, an unsupported algorithm or key policy, attempting to
   create a key whose name already exists, or a failure reported by the underlying OS, device, or
   cryptographic layer. In these cases the call returns its failure value (`nullptr`, `false`, or
   `0`) *and* leaves a non-empty error.
3. **Empty on a clean outcome.** A clean result never sets an error, even when the return value is
   negative. This includes success, a `verify` that returns `false` solely because the signature
   does not match the data, and `KeyPair::Open` returning `nullptr` because the requested key does
   not exist. In all of these `mpss::get_error()` is empty. Success is guaranteed to leave it empty
   even where the backend had to recover from a failed internal step, such as an existence probe or
   a fallback to a second provider.
4. **Thread-local and immediate.** The last error is stored per thread and is only meaningful
   immediately after a failed call on the same thread. Distinguish the two negative cases by pairing
   the return value with `get_error()`: a `false`/`nullptr` result *with* an empty error is the
   clean outcome of rule 3, while a non-empty error is the operational failure of rule 2.

The C interface (`mpss-openssl`) exposes the same contract through `mpss_get_error()`,
`mpss_has_error()`, and `mpss_clear_error()`.

##### Availability queries

`is_algorithm_available()` and `get_available_algorithms()` need one clarification, because their
return value is an *answer* rather than a success indicator. Returning `false` (or omitting an
algorithm from the list) means "this algorithm does not work here" — that is the query succeeding,
so it leaves no error. How a backend decides is up to the backend: the operating-system backends probe
at runtime by creating, signing with and deleting a scratch key, while the YubiKey backend answers from
static capability and so reports availability even with no device attached. Whatever a probe's steps
report describes the scratch key, not the question that was asked, so it is logged but never left as
the last error.

An error is set only when the query cannot be answered at all: an unknown algorithm, an unknown
backend name, or no backend registered. So a `false` result with an empty error means "not
available", while a `false` result with a non-empty error means "could not determine" — the same
rule 2 / rule 3 distinction that applies everywhere else.

##### Internal errors and the OpenSSL error queue

`mpss-openssl` adds one case the four rules above do not cover. Its functions are reachable from C —
the provider callbacks through OpenSSL's dispatch tables, the rest as a plain C API — and a C++
exception must not cross that boundary, so each one catches internally and returns its failure
value. Allocation failure is the realistic cause.

Such a failure leaves **no MPSS diagnostic**: the operation cleared the last error on entry (rule 1)
and never reached the point where it would set one, so `mpss_has_error()` is normally `false`. Read
through rules 2 and 3 alone, an internal error is therefore indistinguishable from a clean negative
— "the storage could not be read" rather than "the delete never ran". (A name that simply held no
key is not a negative at all: deleting it succeeds, because the name already holds nothing.)

So these functions additionally raise on **OpenSSL's error queue**, as `ERR_LIB_PROV` with reason
`ERR_R_INTERNAL_ERROR`, which prints as:

```
error:1C8C0103:Provider routines::internal error
```

**If you use MPSS through OpenSSL** — `EVP_PKEY_sign`, `OSSL_DECODER`, `OSSL_STORE` and so on —
nothing changes. Inspect the error queue after a failure exactly as with any other provider; these
entries simply make it more specific.

**If you call the C API directly**, keep using the documented pattern: the return value plus
`mpss_has_error()`. The queue is worth consulting only when a failure makes no sense — a delete that
reports nothing to delete for a key you are confident exists, say — which is precisely when
"internal error" and "clean negative" need telling apart:

```c
if (!mpss_delete_key(name)) {
    if (mpss_has_error()) {
        fprintf(stderr, "delete failed: %s\n", mpss_get_error());   // rule 2
    } else {
        /* Rule 3, or an internal error. Drain the queue to tell them apart: look for
           ERR_LIB_PROV with reason ERR_R_INTERNAL_ERROR. */
        unsigned long err;
        while ((err = ERR_get_error()) != 0) {
            fprintf(stderr, "  %s\n", ERR_error_string(err, NULL));
        }
    }
}
```

Checking the queue on every call is not expected, and the two channels are independent: MPSS's last
error is thread-local to MPSS, while the queue is OpenSSL's own per-thread queue.

Note that a non-empty queue does **not** by itself mean MPSS failed internally. OpenSSL leaves its
own entries there for its own reasons, and when the YubiKey backend is built, core MPSS calls
OpenSSL too — so the queue may carry entries from a step MPSS recovered from. Core MPSS itself never
raises; only `mpss-openssl` does. Match on `ERR_LIB_PROV` with `ERR_R_INTERNAL_ERROR` rather than on
the queue being non-empty, and clear it (`ERR_clear_error()`) before an operation whose queue state
you intend to inspect afterwards.

### Logging

MPSS provides a simple logging API (see [mpss/log.h](mpss/log.h)) that can be adapted to work with almost any logging system.
By default, the library logs to `std::cout` and `std::cerr` using the logger defined in [mpss/stdout_log.cpp](mpss/stdout_log.cpp).

To create a custom logger, include [mpss/log.h](mpss/log.h) in your source file and create an instance of `std::shared_ptr<mpss::Logger>` using `mpss::Logger::Create`.
This function takes as input three arrays of operation handlers (wrapped in `std::function`) for (1) the actual logging operations, (2) manual flush events, and (3) closing the log.
Any of the handlers can be left empty, in which case the corresponding operation is simply not called.
For a simple example, see [mpss/stdout_log.cpp](mpss/stdout_log.cpp).

Once a `std::shared_ptr<mpss::Logger>` instance has been created, it can be used to log messages at different log levels (see `mpss::LogLevel` in [mpss/log.h](mpss/log.h)).
A minimum log level can be set so that messages at any lower level are silently ignored.
The default log level is `mpss::LogLevel::INFO`.

After calling `close()` on a logger, all handlers are reset and subsequent log calls are silently dropped.
To restore logging, call `mpss::ResetDefaultLogger()` to reinstall the default logger, or use `mpss::GetOrSetLogger` to install a new custom logger.

For callers that cannot use the C++ API, [mpss/log_c.h](mpss/log_c.h) declares a C-compatible view of the same global logger: the `mpss_log_level_t` levels, plain function-pointer handler types, and the `mpss_log_*` functions (`mpss_log_set_level`, `mpss_log_info`, `mpss_log_flush`, `mpss_log_close`, `mpss_log_set_custom_logger`, `mpss_log_reset_default`, and so on).
These are implemented in [mpss/log.cpp](mpss/log.cpp) on top of `mpss::Logger` and act on the same global logger as the C++ API, so the two can be mixed freely.
This header is what lets MPSS's own Objective-C and Swift sources log, and it is what downstream C code (including the OpenSSL provider's consumers, through [mpss-openssl/log.h](mpss-openssl/log.h)) should include.

The global logger and MPSS's internal backend registry are intentionally **never destroyed** at process exit. This keeps MPSS safe to call from a host object's static or global destructor (avoiding the static destruction-order problem), but it has one consequence for custom loggers: a custom logger's `flush`/`close` handlers are **not** invoked automatically at process exit. If your logger buffers output or holds a resource such as a file handle, call `mpss::GetLogger()->close()` (or `mpss_log_close()` from C) during your controlled shutdown to guarantee a final flush. The default `std::cout`/`std::cerr` logger requires no action. For the same reason, avoid performing MPSS-dependent work in your own static/global destructors where ordering relative to the C runtime's stream flushing is undefined.

## Using MPSS with YubiKey PIV

### Setting Up YubiKey PIV
YubiKey PIV uses two types of authentication:

1. **PIN** - A low-entropy secret required for signing operations (user authentication).
2. **Management Key** - A high-entropy secret required for administrative operations like generating or deleting keys.
All YubiKeys come with a well-known factory-default management key.

Most users who self-manage their YubiKeys find that the most convenient approach is to set up their YubiKey with a **PIN-protected management key**.
In this mode,
- The management key is protected with the PIN.
- The authentication flow is simpler, as only the PIN needed (not a separate management key).
- Security is maintained by tying management operations to PIN authentication.

For example, in macOS, to set up your YubiKey PIV with a freshly generated PIN-protected management key, use `ykman` as follows:
```bash
# Install ykman CLI tool
brew install ykman  # macOS
# or: pip install yubikey-manager

# Enable PIN-protected management key mode (recommended)
ykman piv access change-management-key --generate --protect
```

This setup only needs to be done **once per YubiKey** and is the recommended configuration for use with MPSS.
If you prefer to use a custom management key instead of the PIN-protected mode, you can set it via an environment variable:

```bash
# The key is 16, 24, or 32 bytes, depending on how it was generated.
export MPSS_YUBIKEY_MGM_KEY=<32, 48, or 64-character hexadecimal string>
```

Environment variables are not secure storage for secrets. Their values may be visible to other
processes running as the same user, inherited by child processes, or included in crash reports and
CI logs. For production use, prefer the PIN-protected management-key mode described above, which
avoids placing the management key in the process environment.

**Note**: MPSS does not try the publicly known factory-default management key unless
`MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY` is explicitly enabled. This opt-in is intended for initial
setup and testing only:

```bash
export MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY=1
```

If `MPSS_YUBIKEY_MGM_KEY` is set but malformed or incorrect, MPSS fails the operation without trying
the factory default, regardless of this opt-in.

**Note**: MPSS does **not** support the legacy PIN-derived management key mode. If your YubiKey is configured with a PIN-derived management key, MPSS will fail with an error.

### Runtime Configuration

For unattended use, MPSS can read the PIN from an environment variable:

```bash
export MPSS_YUBIKEY_PIN=123456  # Replace with your actual PIN.
```

This has the same exposure risks described above for the management key. MPSS copies the PIN into
memory-cleansing storage, but it cannot remove the original value from the process environment.

If `MPSS_YUBIKEY_PIN` is not set, MPSS prompts for the PIN on the terminal with echo disabled.
Applications can also install a [custom PIN input handler](#custom-interaction-handlers), including
in non-interactive environments. A custom handler can obtain the PIN from an
application-controlled source such as an OS secret store; when one is installed, MPSS ignores
`MPSS_YUBIKEY_PIN`.

If MPSS is compiled with YubiKey support, macOS and Windows will still default to using the OS-native backend.
The library API allows choosing the backend at runtime, but the default can also be changed to the YubiKey PIV backend via an environment variable, as follows:

```bash
export MPSS_DEFAULT_BACKEND=yubikey
```

### Key Policy Configuration

When creating keys, the PIN and touch policies (i.e., when to prompt for these) are baked into the key on the YubiKey and cannot be changed after creation.
These can be configured via environment variables (ahead of key creation), as follows:

```bash
# PIN policy: default, never, once, always
# Default: once
export MPSS_YUBIKEY_PINPOLICY=once

# Touch policy: default, never, always, cached, auto
# Default: cached
export MPSS_YUBIKEY_TOUCHPOLICY=cached
```

The `never` value for either policy permanently disables PIN or touch protection for keys created while it is set, and this cannot be changed after key creation. Because it is a permanent, unrepairable downgrade, MPSS ignores `never` from the environment unless you also set `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1` as an explicit opt-in; otherwise it logs a warning and falls back to the safe default (`once` / `cached`). This gate applies only to the environment variables — a policy set programmatically via `KeyPolicy` is always honored.

See the PIN Policy and Touch Policy items under [YubiKey Backend Limitations and Considerations](#yubikey-backend-limitations-and-considerations) for details on how these affect MPSS operations.

Alternatively, policies can be set programmatically per-key via the [`KeyPolicy`](mpss/key_policy.h) parameter on `KeyPair::Create()`. Programmatic settings override environment variables for that key:

```cpp
#include "mpss/key_policy.h"

// Create a key with explicit PIN and touch policies.
auto key = mpss::KeyPair::Create("my-key", mpss::Algorithm::ecdsa_secp256r1_sha256,
    mpss::KeyPolicy::yubikey_pin_once | mpss::KeyPolicy::yubikey_touch_cached);

// Create a key using env var / default policies (existing behavior).
auto key2 = mpss::KeyPair::Create("my-key2", mpss::Algorithm::ecdsa_secp256r1_sha256);
```

`KeyPolicy` is not specific to YubiKey; see [Key Policies](#key-policies) for the full bit layout,
the other backends' fields, and the rule that a backend rejects a policy it cannot enforce.

### Custom Interaction Handlers

Applications that need custom PIN entry (e.g., a GUI dialog) or touch notifications can install a custom interaction handler:

```cpp
#include "mpss/interaction_handler.h"

class MyInteractionHandler : public mpss::InteractionHandler {
public:
    std::optional<mpss::SecureString> request_pin(const mpss::PinRequestContext &context) override
    {
        if (mpss::PinStatus::wrong_pin == context.last_status) {
            // Show "Wrong PIN" in UI. context.retries_remaining has the count.
        }
        // Show a dialog, read from a secure store, etc.
        // Return std::nullopt to cancel (stops the retry loop).
        return mpss::SecureString{"123456"};
    }
    void notify_pin_result(mpss::PinResult result, int retries_remaining) override
    {
        // Called after each PIN attempt. Update UI (e.g., dismiss dialog on success,
        // show "PIN locked" warning on lockout).
    }
    void notify_touch_needed() override { /* show "touch your YubiKey" UI */ }
    void notify_touch_complete(bool success) override { /* dismiss UI; report failure if !success */ }
};

// Install before any MPSS operations (typically at application startup).
mpss::GetOrSetInteractionHandler(std::make_shared<MyInteractionHandler>());
```

When a custom handler is installed, the `MPSS_YUBIKEY_PIN` environment variable is ignored, and the handler has full control over PIN retrieval. The handler also controls the retry policy - MPSS calls `request_pin` in a loop until it returns `std::nullopt` (cancel), or until the PIN is accepted or locked.

### Device Selection

When only one YubiKey is connected, MPSS uses it automatically. When multiple YubiKeys are present, MPSS requires you to select a device by setting the `MPSS_YUBIKEY_SERIAL` environment variable:

```bash
export MPSS_YUBIKEY_SERIAL=18268739
```
You can find your YubiKey's serial number using `ykman list`.

All operations (key creation, opening, and deletion) will fail with an error if multiple YubiKeys are detected and no serial is specified. When `MPSS_YUBIKEY_SERIAL` is set, MPSS only searches the specified device.

### Summary of Runtime Environment Variables

| Variable | Description | Values | Default |
|----------|-------------|--------|---------|
| `MPSS_DEFAULT_BACKEND` | Override the default backend on platforms with an OS-native backend (Windows, macOS). | `os`, `yubikey` | `os` |
| `MPSS_YUBIKEY_PIN` | YubiKey PIV PIN for signing and PIN-protected management operations. If unset, MPSS prompts interactively. | Any valid PIN string | *(interactive prompt)* |
| `MPSS_YUBIKEY_MGM_KEY` | Custom YubiKey PIV management key (hex-encoded). Only needed if **not** using PIN-protected mode. | 32, 48, or 64 hex characters | *(unset)* |
| `MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY` | Explicitly permit the publicly known factory-default management key for initial setup or testing. | `1`, `true`, `yes`, `on` (case-insensitive); anything else keeps the gate closed | *(unset = factory default refused)* |
| `MPSS_YUBIKEY_SERIAL` | Select a YubiKey by serial number. Required when multiple devices are connected. | Serial number (e.g., `18268739`) | First available device |
| `MPSS_YUBIKEY_PINPOLICY` | PIN policy baked into newly created keys. See [PIN Policy](#yubikey-backend-limitations-and-considerations) for details. | `default`, `never`, `once`, `always` | `once` |
| `MPSS_YUBIKEY_TOUCHPOLICY` | Touch policy baked into newly created keys. See [Touch Policy](#yubikey-backend-limitations-and-considerations) for details. | `default`, `never`, `always`, `cached`, `auto` | `cached` |
| `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE` | Opt-in required to honor `MPSS_YUBIKEY_PINPOLICY=never` or `MPSS_YUBIKEY_TOUCHPOLICY=never` (a permanent hardware downgrade). Without it, `never` from the environment is ignored with a warning and the safe default is used. | `1`, `true`, `yes`, `on` (enable); anything else keeps the gate closed | *(unset = `never` refused)* |


### YubiKey Backend Limitations and Considerations

When using the YubiKey PIV backend, be aware of the following:

1. **Slot Limit**: The YubiKey PIV backend uses the 20 [retired key management slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html) for storing ECDSA keys (and the label certificates described below).
Once all slots are full, you cannot create new keys until you delete existing ones.

1. **Algorithm Support**: Only `ecdsa_secp256r1_sha256` and `ecdsa_secp384r1_sha384` are supported. `ecdsa_secp521r1_sha512` is not available.

1. **PIN Requirement**: Key generation and deletion require the management key. MPSS first attempts these operations without verifying the PIN; this succeeds when the management key is available via `MPSS_YUBIKEY_MGM_KEY`, or when the device still uses the factory default and `MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY` is explicitly enabled. If that fails (e.g., because the management key is PIN-protected), MPSS prompts for the PIN and retries. For signing, MPSS reads the key's PIN and touch policies from the YubiKey metadata. If the PIN policy is anything other than `never`, MPSS will prompt for the PIN (see [PIN Policy](#yubikey-backend-limitations-and-considerations) below for why `once` and `always` behave identically). When both PIN and touch are required, MPSS prompts for the PIN upfront to avoid blocking on touch without user notification. Set the `MPSS_YUBIKEY_PIN` environment variable for non-interactive use; for interactive use, let MPSS prompt on the terminal or install a custom `InteractionHandler` (see [Custom Interaction Handlers](#custom-interaction-handlers)).

1. **Physical Device**: The YubiKey must be plugged in for all operations except standalone verification (which uses software ECDSA).

1. **Key Name Length**: Key names must not exceed 64 characters. This limit is enforced across all backends because the YubiKey backend stores names in the X.509 Common Name (CN) field, which is limited to 64 characters by the X.520 standard.

1. **Key Name Mapping**: MPSS stores key names directly on the YubiKey by writing a minimal X.509 certificate into each slot's certificate object. This means the name-to-slot mapping travels with the device and works on any machine without additional configuration. Note that this uses the certificate object in each PIV slot, so external certificates cannot be stored alongside MPSS-managed keys. The certificate's subject public key is the public key of the key held in the slot, so a label counts only while it still describes that key: if the key is replaced without rewriting the label — by another PIV application, or by a create that was interrupted between generating the key and labeling its slot — the name no longer resolves and MPSS reports the key as not found. This is a consistency check, not a security boundary; anyone who can authenticate with the management key can regenerate a slot key and write a matching label. The certificate is signed by an ephemeral key rather than by the slot key, because signing with the slot key would require a PIN and, under a touch policy, a physical touch on every key creation and deletion. The signature therefore carries no meaning, and the certificate is deliberately not self-issued so that it does not assert a self-signature that would fail to verify.

   > **Compatibility**: Slots labeled by MPSS versions that predate this binding carry certificates whose subject public key is unrelated to the slot, so those labels no longer resolve. A key in such a slot becomes invisible to MPSS, and a slot marked `CN=(available)` by an older version is no longer offered for reuse. Reclaim such a slot by erasing its key material with `ykman piv keys delete <slot>` (requires firmware 5.7 or later; earlier firmware cannot delete PIV keys, in which case only `ykman piv reset` — which destroys everything in PIV — will recover it).

1. **Performance**: Operations are slower than OS-native backends due to USB communication overhead. MPSS does not persist the connection to the YubiKey, but creates a new connection for each operation.

1. **Concurrent Access**: MPSS assumes it is the sole PIV writer to the target device during key creation and deletion. It opens a fresh connection per operation and does not hold a PC/SC transaction across the multi-step create sequence (the libykpiv API exposes no such primitive). A concurrent PIV writer — another MPSS instance, or a third-party PIV tool — that mutates the same device during a `create_key` can therefore clobber a freshly generated key. MPSS detects this specific case: at the end of `create_key` it re-resolves the slot by name and fails the creation (rather than returning a key that may already have been overwritten) if the slot no longer belongs to the new key. Serializing access across separate processes is out of scope; run one PIV writer at a time against a given device.

1. **PIN Policy**: Keys created by MPSS use PIN policy `once` by default (configurable via `MPSS_YUBIKEY_PINPOLICY`). With the connection-per-operation architecture, `once` and `always` behave identically, both requiring the PIN on every MPSS call, because each operation opens a fresh PIV session. The only policy that changes MPSS behavior is `never`, which allows signing operations to succeed without a PIN prompt. Because a `never` key is permanently unprotected, `MPSS_YUBIKEY_PINPOLICY=never` is honored only when `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1` is also set (otherwise MPSS warns and uses `once`); a policy set programmatically via `KeyPolicy` is not gated. Note that key creation and deletion operations need access to the management key, which, if PIN-protected, will require the PIN no matter what (`MPSS_YUBIKEY_PINPOLICY` has nothing to do with this).

1. **Touch Policy**: Keys created by MPSS use touch policy `cached` by default (configurable via `MPSS_YUBIKEY_TOUCHPOLICY`). The `cached` policy requires a physical touch once per 15-second window, balancing security and usability. When a key has a touch policy other than `never`, the YubiKey will wait for a physical touch before completing signing operations. MPSS notifies the application via the `InteractionHandler` (`notify_touch_needed` / `notify_touch_complete`) so it can display appropriate UI; `notify_touch_complete` receives whether the operation succeeded. If the user does not touch the device within the YubiKey's timeout window (typically ~15 seconds), the signing operation fails. To disable touch entirely, set `MPSS_YUBIKEY_TOUCHPOLICY=never`; because this is a permanent downgrade, it is honored only when `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1` is also set (otherwise MPSS warns and uses `cached`).

1. **Key Deletion**: How a slot is freed depends on what the device can do.

   Firmware 5.7 and later can erase a PIV slot outright, so MPSS destroys the key and removes the certificate that labeled it. The slot is left genuinely empty and `ykman piv info` no longer lists it. This is the preferred path: the device's FIPS 140-3 security policy documents the erase as zeroizing the private key, whereas generating over a slot is not documented to do so.

   Earlier firmware has no erase command. There, MPSS renders the key unusable by overwriting it with a newly generated dummy key, then writes a marker certificate with `CN=(available)` to indicate the slot is free for reuse. A key deleted this way shows up as follows:
   ```
   Slot 82 (RETIRED1):
     Private key type: ECCP256
     Public key type:  ECCP256
     Subject DN:       CN=(available),OU=mpss,O=Microsoft
     Issuer DN:        CN=mpss slot label (not an issuer),O=Microsoft
   ```
   Slots bearing this marker are treated as free by MPSS so that they may be overwritten with new keys. The original private key material is destroyed by the overwrite. The marker certificate is bound to the dummy key in the same way as a named label (see [Key Name Mapping](#yubikey-backend-limitations-and-considerations) above), so a slot is only offered for reuse when the marker describes the key actually sitting in it; a marker written over a live key by some other application does not make that key's slot reusable.

### Running Tests with a YubiKey

> **WARNING**: Do not run the unit tests against a YubiKey that contains keys you care about. The test suite creates, signs with, and deletes keys on the device. If something goes wrong (e.g., a test is interrupted mid-run), slots may be left in an inconsistent state.
>
> Additionally, providing an incorrect PIN will decrement the YubiKey's PIN retry counter. After three consecutive wrong attempts, **the PIN will be locked** and you will need the PUK to unlock it. If the PUK is also exhausted, the only recovery is to reset the entire PIV module with `ykman piv reset`, which **destroys all keys and certificates** stored in PIV.
>
> Use a dedicated test YubiKey or ensure you can reset the PIV module if needed.

To run the tests with the YubiKey backend (assuming [PIN-protected management key](#setting-up-yubikey-piv) is set):
```bash
MPSS_DEFAULT_BACKEND=yubikey MPSS_YUBIKEY_PIN=123456 out/build/macos-arm64-with-yubikey-debug/bin/mpss_tests
```
If you do not supply the PIN, you will see the default terminal-based interaction handler requesting the PIN.
Since the default touch policy is `cached`, you will see the touch prompt from the default interaction handler. To skip touch during testing, set `MPSS_YUBIKEY_TOUCHPOLICY=never MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1` (the opt-in flag is required because `never` is a permanent policy downgrade).

## OpenSSL Provider (mpss-openssl)

The MPSS OpenSSL provider enables seamless integration with OpenSSL 3.x applications by exposing MPSS functionality through the standard OpenSSL API. This allows existing OpenSSL-based applications to leverage hardware-backed secure key storage without code changes.

### Provider Components

The OpenSSL provider consists of several key components:

- **Provider Interface ([provider/provider.h](mpss-openssl/provider/provider.h) and [.cpp](mpss-openssl/provider/provider.cpp))** - Main provider registration and dispatch logic
- **Key Management ([provider/keymgmt.h](mpss-openssl/provider/keymgmt.h) and [.cpp](mpss-openssl/provider/keymgmt.cpp))** - Handles key generation, loading, and management operations
- **Signature Operations ([provider/signature.h](mpss-openssl/provider/signature.h) and [.cpp](mpss-openssl/provider/signature.cpp))** - Implements ECDSA and X.509 certificate signing using MPSS keys
- **Digest Operations ([provider/digest.h](mpss-openssl/provider/digest.h) and [.cpp](mpss-openssl/provider/digest.cpp))** - Wraps OpenSSL hash algorithm implementations
- **Encoder ([provider/encoder.h](mpss-openssl/provider/encoder.h) and [.cpp](mpss-openssl/provider/encoder.cpp))** - Handles key encoding and serialization for interoperability
- **Decoder ([provider/decoder.h](mpss-openssl/provider/decoder.h) and [.cpp](mpss-openssl/provider/decoder.cpp))** - Recognizes a key reference PEM and turns it back into a provider key, so a persisted key can be reloaded by name through OpenSSL's standard decode path
- **Store ([provider/store.h](mpss-openssl/provider/store.h) and [.cpp](mpss-openssl/provider/store.cpp))** - Implements the `mpss:<key_name>` URI used to open and delete existing keys through `OSSL_STORE`
- **Key References ([provider/reference.h](mpss-openssl/provider/reference.h) and [.cpp](mpss-openssl/provider/reference.cpp))** - Builds and parses the `<backend>\0<key_name>` blob that both the store loader and the decoder hand to key management
- **Core API ([api.h](mpss-openssl/api.h) and [.cpp](mpss-openssl/api.cpp))** - Declaration of the `OSSL_provider_init` function, as well as C APIs for a few key management operations that are outside the purview of OpenSSL
- **Interaction Handler ([interaction_handler.h](mpss-openssl/interaction_handler.h) and [.cpp](mpss-openssl/interaction_handler.cpp))** - C API for installing custom PIN-request and touch-notification callbacks when using the YubiKey backend
- **Logging API ([log.h](mpss-openssl/log.h))** - A compatibility header that forwards to [mpss/log_c.h](mpss/log_c.h), where the `mpss_log_*` C logging API is declared. The implementation lives in the core library ([mpss/log.cpp](mpss/log.cpp)), so there is no separate `mpss-openssl` logging source file

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
    OSSL_PARAM_construct_utf8_string("mpss_key_name", my_key_name, 0),
    OSSL_PARAM_construct_utf8_string("mpss_algorithm", algorithm, 0),
    // Optionally specify a backend (e.g., "os" or "yubikey"). If omitted, the default backend is used.
    // OSSL_PARAM_construct_utf8_string("mpss_backend", backend_name, 0),
    // Optionally specify a backend-specific key policy. If omitted, backend defaults apply.
    // uint64_t policy = MPSS_KEY_POLICY_APPLE_SECURE_ENCLAVE_USER_PRESENCE;
    // uint64_t policy = MPSS_KEY_POLICY_YUBIKEY_PIN_ONCE | MPSS_KEY_POLICY_YUBIKEY_TOUCH_CACHED;
    // OSSL_PARAM_construct_uint64("mpss_key_policy", &policy),
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

An existing key is reopened by name through OpenSSL's `OSSL_STORE` interface. The provider registers
the `mpss` URI scheme, so a key stored under the name `my-openssl-key` is addressed as
`"mpss:my-openssl-key"`. The key material never leaves the secure backend; the store yields an
`EVP_PKEY` that references the hardware-backed key and can be used for signing, certificates, and
public-key extraction.

**The `"provider=mpss"` property query is required.** OpenSSL uses it to select the MPSS key
management when it materializes the key from the store. If it is omitted, OpenSSL falls back to the
default provider's EC implementation, which cannot open an MPSS key, and the reopen silently yields
no key.

```cpp
// Open an existing MPSS key by name.
OSSL_STORE_CTX *store =
    OSSL_STORE_open_ex("mpss:my-openssl-key", libctx, "provider=mpss", nullptr, nullptr, nullptr, nullptr, nullptr);

EVP_PKEY *existing_pkey = nullptr;
while (OSSL_STORE_eof(store) == 0)
{
    OSSL_STORE_INFO *info = OSSL_STORE_load(store);
    if (info == nullptr)
    {
        continue;
    }
    if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
    {
        existing_pkey = OSSL_STORE_INFO_get1_PKEY(info);
    }
    OSSL_STORE_INFO_free(info);
}
OSSL_STORE_close(store);

// existing_pkey now holds the hardware-backed key. Extract the public key (SPKI) in PEM format.
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
```

#### 4. Provider-Specific Parameters

The MPSS OpenSSL provider exposes custom parameters through `OSSL_PARAM` for key generation and key introspection.

**Settable parameters** (passed via `EVP_PKEY_CTX_set_params` during key generation):

| Parameter | Type | Required | Description |
|---|---|---|---|
| `mpss_key_name` | UTF-8 string | Yes | A persistent name under which the key is stored in the secure environment. Must be unique and must not exceed 64 characters. |
| `mpss_algorithm` | UTF-8 string | Yes | The signature algorithm suite, e.g., `"ecdsa_secp256r1_sha256"`. (Only used for key generation; opening an existing key is done through `OSSL_STORE`, see above.) |
| `mpss_backend` | UTF-8 string | No | The backend to use (e.g., `"os"` or `"yubikey"`). If omitted, the default backend is used. Use `mpss_get_available_backends()` to list available backends. |
| `mpss_key_policy` | uint64 | No | Backend-specific key policy flags (e.g., Apple Secure Enclave user presence or YubiKey PIN/touch policy). Use the `MPSS_KEY_POLICY_*` constants from `mpss-openssl/api.h`. If omitted, defaults to `MPSS_KEY_POLICY_NONE` (backend defaults apply). |

**Gettable parameters** (queried via `EVP_PKEY_get_params` on an existing key):

| Parameter | Type | Description |
|---|---|---|
| `mpss_key_name` | UTF-8 string | The key's persistent name. |
| `mpss_algorithm` | UTF-8 string | The key's algorithm suite (canonical form). |
| `mpss_backend` | UTF-8 string | The backend that created or opened the key. |
| `is_hardware_backed` | int | `1` if the key is stored in hardware (e.g., Secure Enclave, YubiKey), `0` otherwise. |
| `storage_description` | UTF-8 string | Human-readable description of the storage location (e.g., `"Keychain"`, `"YubiKey PIV"`). |

The standard OpenSSL parameters `OSSL_PKEY_PARAM_BITS`, `OSSL_PKEY_PARAM_SECURITY_BITS`, `OSSL_PKEY_PARAM_MANDATORY_DIGEST`, and `OSSL_PKEY_PARAM_DEFAULT_DIGEST` are also supported.

#### 5. Certificate Authority and Certificate Chain Creation

A complete end-to-end example of creating a CA certificate with an MPSS-backed key and signing end-entity certificates with it is shown in [tests/mpss_openssl_e2e_test.cpp](tests/mpss_openssl_e2e_test.cpp).

#### 6. Secure Key Cleanup

When an MPSS secret key is no longer needed, it can be securely deleted from the secure environment.
There are two equivalent ways to do this.

**Through OpenSSL (`OSSL_STORE_delete`).** This is the OSSL-native counterpart to opening a key
(section 2 above): the key is addressed by the same `mpss:<key_name>` URI, `"provider=mpss"` selects
the MPSS provider, and an optional `mpss_backend` parameter selects the backend (as with key
generation and opening). This is the natural choice for an application already using an OpenSSL
library context.

```cpp
// Clear "my-old-key" through the MPSS provider. Returns 1 once the name holds no key, which
// includes a name that held none to begin with, and 0 when the storage could not be cleared.
int deleted = OSSL_STORE_delete("mpss:my-old-key", libctx, "provider=mpss", nullptr, nullptr, nullptr);
if (deleted == 1) {
    // Key was deleted from secure storage.
}

// To delete from a specific backend, pass an mpss_backend parameter:
OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("mpss_backend", (char *)"yubikey", 0), OSSL_PARAM_END};
OSSL_STORE_delete("mpss:my-old-key", libctx, "provider=mpss", nullptr, nullptr, params);
```

**Through the C API (`mpss_delete_key`).** This is a lightweight helper that deletes a key by name
without requiring an OpenSSL library context or a loaded provider — convenient for cleanup utilities.
Use `mpss_delete_key_from_backend` to target a specific backend.

```cpp
#include "mpss-openssl/api.h"

const char *ca_key_name = "my-old-key";
bool deletion_success = mpss_delete_key(ca_key_name);
if (deletion_success) {
    // Key was deleted from secure storage.
} else {
    // Failed to delete key.
    const char *error_msg = mpss_get_error();
    fprintf(stderr, "Error: %s\n", error_msg);
}
```

**Important notes:**
- Only delete keys when you are certain they are no longer needed for signing operations.
There is no way to bring back deleted secret keys.
- Existing certificates remain valid when a secret key is deleted and can still be verified using the public key.
- It may not be easy to list existing keys (or rather, their "names") in the secure environment.
MPSS does not provide such functionality, but individual OS backends might have APIs for enumerating the storage content identifiers.

#### 7. Loading a Key from a Key Reference PEM

Sections 1 and 2 above address a key by name from inside the application. Many OpenSSL-based
programs instead expect to be pointed at a *file* containing a private key, and cannot be changed to
call MPSS or `OSSL_STORE` directly. An MPSS key has no private material that could be written to such
a file.

A **key reference PEM** bridges that gap. It carries the key's *name*, not the key:

```
-----BEGIN MPSS KEY REFERENCE-----
b3MAbXkta2V5
-----END MPSS KEY REFERENCE-----
```

The body is the backend name, a single NUL, and the key name (`os\0my-key` in the example above),
base64-encoded. It holds no secret, and the label is deliberately not `PRIVATE KEY` so the file
cannot be mistaken for PKCS#8.

**Writing a reference.** The reference is produced through the standard encoder API, selecting the
`MpssKeyReference` output structure:

```cpp
// key is an EVP_PKEY previously created or opened through the MPSS provider.
OSSL_ENCODER_CTX *ectx =
    OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_PRIVATE_KEY, "PEM", "MpssKeyReference", "provider=mpss");
BIO *out = BIO_new_file("my-key.pem", "w");
OSSL_ENCODER_to_bio(ectx, out);
BIO_free(out);
OSSL_ENCODER_CTX_free(ectx);
```

The reference records the backend the key was actually opened on, so a key created on a specific
backend cannot later be resolved to a different, same-named key on the default one.

**Reading a reference.** No special API is needed, and unlike the `OSSL_STORE` path in section 2, no
property query is required either: the reference itself identifies the provider that must materialize
the key. It is enough that the MPSS provider is loaded in the library context. An application that
knows nothing about MPSS, and simply reads what it believes is a private key file, reopens the
hardware-backed key:

```cpp
BIO *in = BIO_new_file("my-key.pem", "r");
EVP_PKEY *key = PEM_read_bio_PrivateKey_ex(in, nullptr, nullptr, nullptr, libctx, nullptr);
BIO_free(in);

// key now signs in the secure environment; no private material was ever in the file.
// ... use key, then free it.
EVP_PKEY_free(key);
```

**Notes:**
- `PEM_write_bio_PrivateKey` does *not* produce a reference. It requests the PKCS#8 `PrivateKeyInfo`
structure, which is defined to contain the private key, so no encoder can satisfy it for a key whose
private material cannot leave the secure environment. The call fails rather than writing anything.
- A reference is a pointer to a key, not the key. Anyone able to replace the file can change which
key an application uses, and which backend it is opened from. Protect it as you would a
configuration file that selects a credential.
- Reading a reference for a key that no longer exists fails; the reference is not a cached copy.

### Building mpss-openssl 

To build the OpenSSL provider, configure the CMake project with one of:

- `MPSS_BUILD_MPSS_OPENSSL_STATIC=ON` for a static library build
- `MPSS_BUILD_MPSS_OPENSSL_SHARED=ON` for a shared library build

Building for iOS requires extra care.
For instructions, see [the example above](#ios).

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
