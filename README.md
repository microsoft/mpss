# MPSS - A Multi-Platform Secure Signing Library

MPSS provides a C++20 API for creating, storing, and using signing keys without exporting their
private material. An OpenSSL provider exposes the same keys to OpenSSL 3.2 and later.

| Platform | API |
|----------|-----|
| Windows | TPM-backed [MS_PLATFORM_KEY_STORAGE_PROVIDER](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider) if available; [VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) otherwise; software-protected storage if neither |
| macOS / iOS | [Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave) for P-256, and for P-384 where the platform allows it; [Keychain](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain) otherwise |
| Android | [AndroidKeyStore](https://developer.android.com/privacy-and-security/keystore), requesting StrongBox for P-256 first; otherwise protection depends on the device and may be TEE-backed or software |
| Linux | [YubiKey PIV](https://developers.yubico.com/PIV/) (default, see below) |
| YubiKey (optional) | [YubiKey PIV](https://developers.yubico.com/PIV/) (cross-platform: Windows, macOS, Linux only) |

Enable YubiKey support with `MPSS_BACKEND_YUBIKEY=ON`. It is optional on Windows/macOS,
required on Linux, and unsupported on iOS/Android.

**Windows protection is per key.** Creation tries TPM, VBS, then software storage; unsupported
TPM algorithms can fall back without leaving an error. If the TPM provider cannot be opened and the
TPM Base Services do not report that the machine has no TPM, creation fails rather than falling
back, because a TPM may already hold the name. There is no minimum-storage-tier parameter. Read
`key_info().storage_tier` for `StorageTier::windows_tpm`, `StorageTier::windows_vbs`, or
`StorageTier::windows_software`.
`is_hardware_backed` is **true only for TPM keys**. A VBS key is not exportable either, but its
isolation rests on the hypervisor and its protection at rest on conditions MPSS cannot check, so it
reports false; read the tier rather than the flag to tell VBS from software storage.

## Threat Model

MPSS exposes no way to retrieve private key material: `extract_key()` returns the public key, and
the OpenSSL provider's reference encoder emits the key's location and public key, never private
material. Signing happens inside the backend. How much that is worth depends on the storage a key
actually obtained, which is what `key_info()` reports.

`is_hardware_backed` is true when the private key is held outside the operating system's reach, in
storage the platform vendor classifies as secure hardware: TPM on Windows, the Secure Enclave on
Apple, Trusted Environment or StrongBox on Android, and the secure element of a YubiKey. It is
false for the Apple Keychain tier and for plain software storage, and false for Windows
Virtualization Based Security, which is not a weak tier but a conditional one: the isolation is
enforced by the hypervisor, and what protects the key at rest depends on Secure Boot and on a TPM
being present, neither of which MPSS can establish.

`key_info()` reports one fact three ways. `storage_tier` is the fact: a `StorageTier` enumerator
such as `StorageTier::apple_secure_enclave`, established by the backend from the key itself.
`is_hardware_backed` and `storage_description` are what the table in `mpss/storage_tier.h` says that
tier reports, derived from it rather than decided alongside it, so the three cannot disagree.
Compare `storage_tier` whenever the difference between two tiers that give the same flag matters:
`windows_tpm` and `yubikey_piv` both report true, and `apple_keychain` and `windows_vbs` both report
false for unrelated reasons. `get_storage_tier_info()` answers for a tier without a key in hand.

Tiers are names, not a rank: compare one for equality, never order it. The values run in increasing
protection within a platform, so `tier >= StorageTier::windows_tpm` passes every test written on one
platform and then accepts `apple_keychain` and `android_software`, neither of which is hardware
backing. `is_hardware_backed` is what ranks tiers against each other.

**An algorithm constrains which tiers are eligible, but does not settle which one a key gets.** On
Apple, MPSS asks the Secure Enclave to hold every key and establishes from the key itself whether it
did. Which algorithms the enclave accepts, and what happens when it declines, differ between the two
paths Apple provides; see [Apple: which store answers](#apple-which-store-answers). A key reports
the protection it actually has, so a caller that reads `key_info()` sees a change in platform
behavior rather than silently losing a guarantee it believed it had.

### Apple: which store answers

Apple offers two ways to reach the enclave. MPSS uses both, and they establish the tier differently.

| Path | Taken for | Where the key lives | How the tier is established |
|---|---|---|---|
| CryptoKit | P-256, where the platform reports an enclave | The enclave holds the key. MPSS stores its `dataRepresentation`, a blob wrapped to that enclave and inert on any other device, as a Keychain generic password | The type. A `SecureEnclave.P256.Signing.PrivateKey` cannot be held anywhere else, so there is nothing to read back |
| Security framework | P-384 and P-521, and anything where no enclave is reported | A Keychain key, held in the enclave if it accepted the request | Read back from `kSecAttrTokenID` on the key that was created |

The CryptoKit path needs no entitlement, because what it persists is a password item rather than a
key the enclave owns. The Security framework path asks for a persistent enclave key, which on macOS
requires a provisioning profile. A command-line tool has none unless it is wrapped in an app-like
bundle, so its request fails with `-34018` and the key is created in software. An iOS application
does have one, which is why the same P-384 request reaches the enclave on a phone and not in a
terminal.

**A P-256 create does not fall back.** Where an enclave is reported, it is the only place MPSS will
put that key: if the enclave declines, creation fails rather than quietly returning a software key.
Only the Security framework path falls back, and it reports `apple_keychain` when it does.

Observed:

| | P-256 | P-384 | P-521 |
|---|---|---|---|
| iPhone | Secure Enclave | Secure Enclave | Keychain |
| Simulator | Keychain | Keychain | Keychain |

Apple documents the enclave as working with P-256 only, so P-384 rests on behavior that is not
promised and may stop being offered. MPSS assumes it in neither direction.

The simulator accepts `kSecAttrTokenIDSecureEnclave` and hands the attribute back, but signs at
software speed and keeps the key in a file on the host. MPSS reports those keys as `apple_keychain`:
there is no enclave for them to be in.

### What protection covers

**What a hardware-backed key defends against.** A key generated inside secure hardware and never
exported cannot be read out of a backup, scraped from process memory, or committed to a repository,
and whoever reaches the host cannot carry it away to use elsewhere afterwards, so their use of it
lasts only as long as their access to the device. A Windows VBS key is not exportable either: the
isolated environment holding it is not readable by the rest of the operating system. The remaining
tiers do not isolate the key that way. Windows marks software-tier keys non-exportable through CNG,
which is an access policy rather than isolation, and an Apple software Keychain key can be read out
by code that reaches the keychain item, yielding the private key rather than anything sealed to the
device, so it can be used elsewhere. An enclave-backed key differs in exactly that respect: a
`SecKey` the enclave holds refuses to give up its private key at all, and the representation
CryptoKit stores for a P-256 enclave key is wrapped to that enclave and inert on any other device.

**What no tier defends against.** Any code running in the calling process can ask MPSS to sign, and
the OpenSSL provider is the same trust boundary; a compromised application never has to defeat MPSS
to use a key it can already reach. MPSS runs inside the process it is protecting, so a check MPSS
makes is advisory: what holds is what the storage enforces, and what a relying party verifies off
the machine. Hardware backing bounds the theft of a key, not its use.

A key name is an identifier, not a secret. Who else can reach a key depends on the backend:

- **Windows.** Keys belong to the current user, and MPSS sets no PIN or UI policy on them: other
  programs running as that user can open, use and delete a key by name, whether or not they use
  MPSS.
- **iOS.** A key goes into the application's default
  [Keychain access group](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps):
  the first group its Keychain Sharing capability lists, or else its app ID. An iOS application
  running on a Mac follows the same rules.
  - *Updates* keep the key.
  - *Sharing:* to share keys with your extensions and other applications, list the same Keychain
    Sharing group first in each of them before they create keys. Only applications from your team
    can list it.
  - *Other applications* cannot see, use or delete the key.
- **macOS.** A key normally lives in the user's login keychain, a
  [file-based keychain](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
  in which it belongs to the application that created it.
  - *Updates* you sign the same way, with Developer ID or for the Mac App Store, keep the key
    without the user being asked: the keychain recognizes the application by its
    [code signature](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html),
    not by where it is installed. Development builds signed with your Apple Development certificate
    keep their keys across rebuilds.
  - *Sharing:* any other application, your own helpers and extensions included, can use the key
    only if the user allows it in a system dialog, and is refused where no dialog can be shown. To
    avoid dialogs when several of your programs sign with the same key, let one program create the
    key and do all the signing: the others send that program the hashes they need signed, for
    example over XPC, and get the signatures back. Make sure that program signs only for your own
    programs, not for any program that asks; XPC can check each caller's code signature for you.
  - *Other applications*, sandboxed or not, can create a key under a name yours uses and delete a
    software (`apple_keychain`) key without the user being asked. If the user lets one read a P-256
    enclave key, even once, it can keep a copy that works only on that Mac and sign with it from
    then on.
  - *Exception:* a key the [Security framework path](#apple-which-store-answers) places in the
    enclave, which needs a provisioned application, is kept in the data protection keychain and
    follows the iOS rules, though other applications can still create a key under its name.
- **Android.** A key belongs to the application's Linux user ID, which its updates keep and which
  differs in each Android user and work profile. Another application shares that ID only if both
  declare the same `android:sharedUserId` and are signed with the same certificate, a mechanism
  Android has deprecated. Android 16 lets an application grant one of its keys to another
  application; MPSS does not do so, and does not open a key granted to it.
- **YubiKey.** A key belongs to the device. Any program with access to the device can read the key's
  name, use the key once its PIN and touch policies are satisfied, and replace or delete it with the
  management credentials.

Wherever other code can create a key under a name your application uses, it can take that name
first or make it ambiguous, and where it can also delete your key, it can put its own in its place.
To recognize the same key over time, keep its public key where that code cannot change it and
compare against it, as [Key Management](#key-management) describes. The OpenSSL provider runs
inside whichever program loads it, so that program is the application in the rules above; on macOS,
the `openssl` command is a different application from yours.

Android and YubiKey refuse a key that was not generated in the key store itself, which they read
from origin metadata the store records at generation. That says how a key came to be there rather
than how it is protected now: on Android the check is independent of which tier the key store put
the key in, which `key_info()` reports separately. The Windows and Apple paths do not establish
origin at all, and `key_info()` reports where a key is now rather than where it came from.

**Requiring the user for each signature** narrows the window in which a compromised host can sign.
Only some backends offer it:

| Backend | Per-signature policy `KeyPair::Create` accepts |
| --- | --- |
| YubiKey PIV | `yubikey_touch_always` |
| Apple Secure Enclave | `apple_secure_enclave_user_presence` |
| Windows | None; a nonzero `KeyPolicy` is rejected |
| Android | None; a nonzero `KeyPolicy` is rejected |

Windows and Android have platform facilities for this that MPSS does not expose.
`yubikey_pin_always` requires PIN verification for every operation, but a PIN can come from
`MPSS_YUBIKEY_PIN` or from a handler that holds one, so it governs credential use rather than
showing that someone was present. Unless told otherwise MPSS creates YubiKey keys with the `cached`
touch policy, under which the device asks for another touch only once more than 15 seconds have
passed since the last one; `always` spends a touch on every signature. Apple evaluates its
user-presence check inside the Secure Enclave rather than trusting a result the application
supplies, though the application still chooses when to ask and what digest to submit.

A touch or a presence check establishes that someone was there, not that they agreed to the
operation that ran. Neither shows the user what is about to be signed, and on a compromised host the
prompt asking them is written by whoever controls it. An application that needs the user to confirm
*what* it signs needs a display that host does not control, or a confirmation channel that does not
pass through it.

**Deleting a key is not revocation.** A successful delete removes the stored entry, within the
backend scope and partial-failure rules described below. It does not invalidate signatures or
certificates already made with that key, and it cannot reach a copy held outside the entry it
removed.

## Compiling for different platforms

The OS-native core uses system APIs. Additional dependencies are supplied by vcpkg:
[GoogleTest](https://github.com/google/googletest) for tests,
[libykpiv](https://developers.yubico.com/yubico-piv-tool/) and OpenSSL for YubiKey support,
OpenSSL 3.0 or later for optional C++ key-reference serialization,
and [OpenSSL](https://github.com/openssl/openssl) 3.2 or later for the provider (which includes serialization).

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
YubiKey support; `-shared` selects shared libraries, otherwise static. Desktop `-shared` presets
also link OpenSSL and the other vcpkg dependencies as shared libraries. Android uses shared
libraries and the iOS Simulator preset uses static libraries. Linux offers only `-with-yubikey`
presets, because it has no OS-native backend and MPSS requires at least one backend. Windows names
containing `-mock` also build the NCrypt failure-injection tests (`MPSS_BUILD_WIN32_MOCK_TESTS=ON`).

Each configure preset has a separate `out/build/<name>` directory and vcpkg installation.
With Visual Studio or Xcode, add `--config Debug` or `--config Release` when installing.
Preset names include the target architecture. Linux presets do not cross-compile, so choose the
one matching the host.

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
provider archive, and the core archive with it because the provider enables key-reference
serialization, deliberately leave OpenSSL's symbols undefined so that your own link step resolves
them, which is also why one set of headers serves both the device and simulator slices.
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

MPSS opens only keys the key store generated itself. A key imported into AndroidKeyStore really
does reside in secure hardware and reports hardware backing accordingly, yet whoever imported it
still holds the private material, which is the one thing a report of hardware backing is meant to
rule out. Origin is stamped by the secure hardware at generation and cannot be supplied when
generating, so it answers where the key came from rather than where it now lives. Anything not
generated in the key store is refused by both `Open` and `Create`, including a securely imported
key. Such a key can still be deleted, since deletion addresses the alias without loading the key.

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

MPSS links OpenSSL as a shared library on Android, so that MPSS and the application share one
OpenSSL; the presets build it with the `arm64-android-dynamic` and `x64-android-dynamic` vcpkg
triplets in [triplets](triplets/). Package that `libcrypto.so` with the application, and link the
application's own OpenSSL use to it rather than to a static copy. Android's system `libcrypto.so`
is BoringSSL and is not available to applications.

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

The build packages the Java classes, native libraries, OpenSSL, and shared C++ runtime using the
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

The YubiKey backend requires a PIV-capable YubiKey with the PIV application enabled and **firmware
5.3 or later**. Two things MPSS depends on arrived in that release:
[reading slot metadata](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/metadata.html),
which is how a handle confirms it still holds the key it opened and how a key's origin and policies
are established, and the `cached` touch policy, which is the default MPSS creates keys with. Earlier
firmware is not supported: without metadata MPSS cannot tell what a slot holds, so it refuses rather
than assume. Install the `ykman` CLI separately for device administration. FIPS models also need
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
  cmake --preset linux-x64-with-yubikey-release
  cmake --build --preset linux-x64-with-yubikey-release
  ```

  Use `linux-arm64-...` on arm64 hosts.

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
| `MPSS_WITH_SERIALIZATION=ON` | Enable C++ key-reference DER/PEM serialization using OpenSSL's crypto library, without requiring the provider. Off by default; either provider build enables it automatically. |
| `MPSS_ENABLE_HARDENING=OFF` | Disable security hardening compile and link flags (default is `ON`). |
| `BUILD_SHARED_LIBS=ON` | Select shared core and provider libraries when no explicit MPSS library-type option is enabled. Explicit options take precedence. |

Build shared MPSS libraries against a shared OpenSSL, so that a process has one copy of it. With
vcpkg on macOS or Linux, this means a `-dynamic` triplet such as `x64-linux-dynamic`, as the
`-shared` presets use.

Static targets are named `mpss::mpss_static` and `mpss::mpss_openssl_static`, whereas shared targets are `mpss::mpss` and `mpss::mpss_openssl`.
Single-configuration generators use `CMAKE_BUILD_TYPE` to select `Debug` or `Release`.
On desktop builds, run `bin/mpss_tests` from the build directory (`bin\Debug\mpss_tests.exe` or
`bin\Release\mpss_tests.exe` with Visual Studio). When enabled, run `mpss_win32_mock_tests.exe`
separately from the same configuration directory; shared-core builds do **not** create it, even
with `MPSS_BUILD_WIN32_MOCK_TESTS=ON`.

#### Selecting features through vcpkg

When installing MPSS through its vcpkg port, `mpss[serialization]` enables C++ key-reference serialization without building the provider.
`mpss[openssl]` builds the provider and includes serialization automatically.
Both use the same OpenSSL dependency; YubiKey support already requires OpenSSL but does not itself enable serialization.

When configuring this checkout directly, the `VCPKG_MANIFEST_FEATURES` list also enables the corresponding MPSS capabilities (`openssl`, `serialization`, `yubikey`, and `tests`).
Separate multiple features with semicolons and quote the argument, including in PowerShell:

```powershell
cmake -S . -B build "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" "-DVCPKG_MANIFEST_FEATURES=openssl;serialization"
```

Here `serialization` is redundant because `openssl` implies it; specifying just `serialization` does not enable the provider.
If neither provider library type is selected, the `openssl` feature chooses the same static/shared linkage as the core.
Manifest features are additive requests: a listed feature enables its capability even if the corresponding CMake option is `OFF`.
Removing a feature restores the explicitly configured CMake options; implied settings are not written back to their cache entries.
Conversely, selecting MPSS's CMake options requests the necessary vcpkg dependencies automatically.
Without the vcpkg toolchain, OpenSSL must already be discoverable by `find_package`.

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

The member `delete_key()` requires an open handle, and finishes that handle: once it succeeds the handle is released, and the operations that reach the key fail from then on, as described under [Handle Lifetime](#handle-lifetime).
Use static `KeyPair::Delete` to clear a name without opening it, including an ambiguous name:

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

On Windows, a provider that cannot be opened rules a name out only when it is the TPM provider and the
TPM Base Services report that the machine has no TPM.
Any other provider that cannot be opened leaves the name unresolved: clearing the name fails, and creating
or opening a name that no readable provider holds fails rather than treating that provider as empty.
YubiKey deletion by name requires a valid [slot label](#yubikey-backend-limitations-and-considerations).
In the process that deletes a key, no handle can reach it afterwards, whichever API deleted it.

### Handle Lifetime

A handle holds something for as long as it lives: an OS key handle on Windows, a hold on a cached
key on Apple and Android. Destroying it gives that back, so most callers never release explicitly.

```cpp
// Give up what the handle holds before it goes out of scope.
bool released = handle->release_key();
```

Releasing is optional, and it is final. Afterwards every operation on the handle fails, including
the size requests spelled as `sign_hash` and `extract_key` with an empty buffer. What the handle
recorded when it was opened still answers: `algorithm`, `key_info`, `sign_hash_size` and
`extract_key_size` never reach the key.

The return value reports whether everything the handle held was given up. A `false` return does not
invite another attempt: the handle is finished either way, and releasing it again repeats what the
one attempt reported.

A handle also stops working when the name it opened moves on.
A key can be deleted and created again under the same name while a handle to the old key is still open; that handle does not silently follow the name to the new key.
On Windows, Apple and Android the name is tracked within the process, so this covers a key MPSS itself replaced; one replaced by another process or tool is not seen.
A YubiKey handle instead compares the slot's public key before each operation, so it also notices a key replaced by another tool.
Signing, verification, public-key extraction and deletion through it fail with an error naming the reason:

```text
Key 'my-key' is no longer the key this handle opened.
```

What the handle recorded still answers, as it does after releasing: `algorithm`, `key_info`, `sign_hash_size` and `extract_key_size` never reach the key, and neither do the size requests spelled as `sign_hash` and `extract_key` with an empty buffer.

That is deliberately different from reporting the key as missing, since a caller told a key is absent will reasonably try to create it.
Open the name again to get a handle to whatever holds it now.

### Serializing Key References

`KeyPair::reference()` captures the handle's resolved location, algorithm, and public key into an owning `KeyReference`.
This operation is available in every core build and may access the device, but does not sign a challenge.

With `MPSS_WITH_SERIALIZATION` enabled, include `mpss/serialization.h` to encode and decode references as DER or PEM.
The public functions use C++ types only; no OpenSSL handles or provider registration are needed.
Link the usual core CMake target, which carries the required crypto-library linkage.
The generated `mpss/config.h` defines `MPSS_WITH_SERIALIZATION` when these functions are available, and the installed CMake package exposes the same variable.

```cpp
#include <mpss/mpss.h>
#include <mpss/serialization.h>

auto reference = key_pair->reference();
if (!reference) {
    // Report mpss::get_error().
    return;
}
auto pem = mpss::encode_key_reference_pem(*reference);
if (!pem) {
    // Report mpss::get_error().
    return;
}

// Save *pem, then later parse it without accessing any backend.
auto restored = mpss::decode_key_reference_pem(*pem);
if (!restored) {
    // Report mpss::get_error().
    return;
}
auto reopened = mpss::KeyPair::Open(*restored);
if (!reopened) {
    // Report a missing key or mpss::get_error().
    return;
}
```

`encode_key_reference_der` returns an optional `std::vector<std::byte>`; `decode_key_reference_der` accepts `std::span<const std::byte>`.
Both decoders return an optional `KeyReference`, and all four functions report failures through `mpss::get_error()`.
Encoding and decoding are offline: they validate field syntax, algorithms, and public keys, but do not check backend availability, resolve environment defaults, or open a key.
Encoding preserves the supplied identity rather than replacing it with whatever currently occupies the location.
Backend-specific device rules are enforced when the reference is opened.

A serialized reference records the key's location and expected public key, so reopening can reject a different key at that location.
PEM output uses the `MPSS KEY REFERENCE` label.
The C++ and provider encoders share one implementation and produce identical [key reference PEMs](#loading-a-key-from-a-key-reference-pem) for the same reference.
Output uses 64-character Base64 lines and LF line endings.
The C++ PEM decoder accepts one document of up to 8192 bytes in total; apart from surrounding ASCII whitespace and CRLF line endings, the text must match the encoder's output exactly.
DER input is limited to 4096 bytes and must contain exactly one canonical reference; a compressed or hybrid public-key point is accepted and decodes to the uncompressed public bytes, so only references with uncompressed points re-encode byte for byte.
Neither format contains private key material or credentials.
Protect the reference's integrity: successful decoding does not establish trust in its public key or authenticate a physical device.

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
P-521 where available, but do not assume it will be hardware-backed. Android StrongBox is used only
for P-256, Windows TPM algorithm support varies by device, and the Apple Secure Enclave takes P-256
and, on platforms that allow it, P-384; it refuses P-521. Read `key_info()` rather than inferring
protection from the algorithm.

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
the same thread or the thread exits; copy the string if needed longer. Through the provider,
these diagnostics are accompanied by OpenSSL's own error queue; see
[Errors and the OpenSSL Error Queue](#errors-and-the-openssl-error-queue).

##### Availability queries

`is_algorithm_available()` returns `false` without an error for an unavailable algorithm;
an unknown algorithm/backend or missing default backend sets an error.
OS backends probe using a scratch key. YubiKey answers from static capabilities, even without
a device. Default-backend queries cache positive results, so availability is not a readiness
or storage-tier guarantee.

### Thread Safety

A `mpss::KeyPair` handle is safe to use from several threads at once. `sign_hash`, `verify` and
`extract_key` may run concurrently with each other on one handle, while `release_key` and
`delete_key` exclude everything else, so an operation either completes before a release or is
refused by it. Releasing is one decision however many threads ask at once: the backend release runs
exactly once between them, and the rest are told the handle is released.

`KeyPair::Create`, `KeyPair::Open` and `KeyPair::Delete` may be called concurrently, though two of
them naming the same key run one after the other, so that each sees a settled answer rather than
one another half finished. This ordering holds within one process. MPSS does not coordinate with
other processes, so an application that creates or deletes the same key from more than one process
must order those calls itself. Each handle has its own lock, but that is all it owns: handles
addressing the same key, or the same device, are still coupled through whatever they share.
Deleting a key invalidates every handle to it in the process that deletes it, and a YubiKey serves
one operation at a time whichever handle asks.

Destroying a handle is not an operation. Like any other object, a `KeyPair` must not be destroyed
while another thread is still inside it.

The last-error channel is per-thread, so concurrent calls do not overwrite each other's
diagnostics. See [Error Handling](#error-handling).

An interaction handler is called on whichever thread performs the operation, from inside the locks
that operation is holding, so **it must not call back into MPSS**; such a call is refused and
reports an error. See [Custom Interaction Handlers](#custom-interaction-handlers).

**YubiKey.** One device serves one operation at a time. A PIV session is stateful, since verifying
a PIN and then signing are separate exchanges carried on one connection, so MPSS serializes by
device serial across every handle and thread in the process. A key whose touch policy requires a
touch holds the device while it waits, and other threads addressing that device wait with it.
Different YubiKeys proceed in parallel. Listing devices connects to every reader in turn, and
connecting to a device disturbs what a session has established on it, a verified PIN among that, so
a listing runs only while no session is open on any device.

**Other backends.** Apple, Android and Windows do not serialize by device, so operations on
distinct handles proceed in parallel.

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

Unset variables use `once` / `cached`; an explicit `default` delegates to the firmware defaults,
which are `once` for the PIN and `never` for touch. `never` permanently disables the corresponding
protection for that key. Environment-driven `never`, and `default` for the touch policy, require
`MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE=1`; otherwise MPSS warns and uses its default.

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

`PinRequestContext::target` identifies the backend, device ID (the YubiKey serial number), key name, and reader used by the current connection.
The notification methods receive the same target information as an `InteractionContext`.
Use the device ID to select credentials and distinguish concurrent requests; a reader name is display information, not a stable or authenticated identity.
Context strings are valid only during the callback; copy them when posting work to another thread.

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

    void notify_touch_needed(const mpss::InteractionContext &target) override
    {
        my_ui::show_touch_prompt(target.device_id);
    }

    void notify_touch_complete(const mpss::InteractionContext &target, bool success) override
    {
        my_ui::hide_touch_prompt(target.device_id, success);
    }

    // Optional, but the only place an outcome other than "wrong PIN" is reported.
    void notify_pin_result(const mpss::InteractionContext &target, mpss::PinResult result, int retries_remaining) override
    {
        if (mpss::PinResult::not_attempted == result)
        {
            // No attempt was made, so retries_remaining is unchanged.
            my_ui::hide_pin_dialog(target.device_id);
            return;
        }
        my_ui::report_pin_result(target.device_id, result, retries_remaining);  // ok, wrong_pin, locked, or error.
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
refused and reports an error. Do any MPSS work before the operation that needs the PIN, or after it
returns.

Callers that cannot subclass a C++ interface can install the same four behaviors as plain function
pointers through [mpss-openssl/interaction_handler.h](mpss-openssl/interaction_handler.h), which
declares `mpss_request_pin_handler_t` and the three notification types.
`mpss_set_interaction_handler` supplies this target metadata and an application-owned `user_data` pointer to all four callbacks.

### Device Selection

MPSS automatically selects the sole reachable YubiKey; select a serial explicitly when several are reachable.
Use `get_available_devices("yubikey")` to list reachable serials.

`KeyLocation` specifies the backend, key name, and optional device ID: a positive decimal serial for YubiKey; OS storage accepts no device ID and rejects one with an error.
`key->location()` reports the backend and device actually used.

```cpp
mpss::KeyLocation target{"yubikey", "my-key", "35489220"};
auto key = mpss::KeyPair::Create(target, mpss::Algorithm::ecdsa_secp256r1_sha256);
if (!key) {
    // Report mpss::get_error().
    return;
}

std::optional<mpss::KeyReference> reference = key->reference();
if (!reference) {
    // Report mpss::get_error().
    return;
}

// Persist *reference in trusted application storage, then reopen the same key later.
auto reopened = mpss::KeyPair::Open(*reference);
```

`Open(location)` selects by location only; `Open(reference)` also requires the expected algorithm and public key.
A missing target or key mismatch fails without creating a key, changing the expected public key, or falling back to another device.
`Delete(location)` clears that name on the selected device; for deletion tied to a particular public key, open its reference and use the resulting handle's `delete_key()`.
Location-based calls ignore `MPSS_YUBIKEY_SERIAL`; omitting the device ID requests automatic selection.
`MPSS_YUBIKEY_SERIAL` sets the default serial for calls that take a key name rather than a `KeyLocation`.
Serials are decimal integers from 1 to 4294967295; leading zeros are accepted, with a 256-character input limit.
An invalid value fails the operation, whether it comes from the environment or from an explicit `device_id`; an empty environment value counts as unset.
Existing handles keep their selected device when the default changes.
A serial identifies a target but does not authenticate hardware.

The YubiKey backend does its own OpenSSL work, verifying signatures, reading and writing slot labels, and fingerprinting refused PINs, in an isolated OpenSSL context with the built-in default provider.
It does not inherit the application's provider configuration or FIPS property selection.
The exception is management-key authentication, which creating and deleting keys require: libykpiv performs it, and on macOS and Linux it uses OpenSSL's default library context.
If the application's configuration leaves that context unable to provide the management key's cipher or random number generation, those operations fail with a management-key authentication error, even when the key is correct.
On Windows, libykpiv uses CNG for this instead.

Each device has its own PIN, while `MPSS_YUBIKEY_PIN` holds a single value. MPSS declines to present
a PIN that a device has already refused, and reports that as the reason the operation failed, so a
stale configured PIN cannot spend that device's remaining retries. The record is kept per serial, as
a keyed fingerprint rather than the PIN itself, so a value one device refused is still offered to
another and correcting the PIN takes effect immediately.

The record lasts for the lifetime of the loaded library. If the device PIN is changed elsewhere to a
value MPSS has already seen refused, restart the process so that value is offered again.

### Summary of Runtime Environment Variables

| Variable | Description | Values | Default |
|----------|-------------|--------|---------|
| `MPSS_DEFAULT_BACKEND` | Default backend, selected at initialization | A name from `get_available_backends()` | `os`; `yubikey` on Linux |
| `MPSS_YUBIKEY_PIN` | PIN used by the default handler | Device-valid PIN | Prompt when needed |
| `MPSS_YUBIKEY_MGM_KEY` | Management key when not using PIN-protected mode | 32, 48, or 64 hex characters | Unset |
| `MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY` | Permit factory-default management-key authentication | `1`, `true`, `yes`, `on` (case-insensitive) | Disabled |
| `MPSS_YUBIKEY_SERIAL` | Default YubiKey serial for name-based calls; `KeyLocation` calls ignore it | Positive serial number | Sole reachable device |
| `MPSS_YUBIKEY_PINPOLICY` | New-key PIN policy | `default`, `never`, `once`, `always` | `once` |
| `MPSS_YUBIKEY_TOUCHPOLICY` | New-key touch policy; `never` and `default` (firmware default, also never) need the opt-in below | `default`, `never`, `always`, `cached`, `auto` | `cached` |
| `MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE` | Permit environment-driven `never` policies, including the firmware-default touch policy | `1`, `true`, `yes`, `on` (case-insensitive) | Disabled |

### YubiKey Backend Limitations and Considerations

| Area | Behavior |
| --- | --- |
| Capacity | 20 [retired PIV slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html); delete keys to free space |
| Algorithms | P-256 and P-384; no P-521 |
| Device access | Signing and storage operations require the selected device. Standalone verification with an extracted public key does not |
| Authentication | Creation/deletion request a PIN only after authentication-related failure; other refusals do not trigger a PIN retry |
| PIN lockout | A PIN the device refuses is not presented to it again for the lifetime of the process, so a stale `MPSS_YUBIKEY_PIN` cannot spend the device's remaining retries. See [Device Selection](#device-selection) |
| PIN policy | MPSS reconnects per operation, so `once` need not cache the PIN across signing calls. `never` affects signing, not management authentication |
| Touch policy | `cached` needs a touch only if more than 15 seconds have passed since the last one. The handler is notified whenever the policy is not `never`, so under `cached` a prompt can appear when the cached touch means none is actually required. MPSS sets no timeout of its own; signing blocks until the device gives up, and an untouched key fails the operation |
| Concurrency | Run one PIV writer per device. Multi-step operations are not atomic across processes |

Names live in each slot's label certificate, whose public key must match the slot key.
MPSS ignores mismatched labels and refuses ambiguous names. Labels are not attestations;
a writer with management credentials can replace both key and label. Storing an unrelated
certificate in the slot replaces MPSS's label.

MPSS opens only keys the device generated itself. PIV slot metadata records whether a key was
generated on the device or imported into it, and a key imported into a slot resides in the same
secure element and reports the same protection while whoever imported it still holds the private
material. Such a key is refused by `Open` and is not created over; it can still be deleted, since
deletion addresses the slot rather than vouching for what is in it.

By-name deletion clears keys with matching labels on the selected device and fails if a slot is unreadable.
Keys without valid labels require direct slot administration. Existing handles retain the serial,
the slot, and the public key the slot held when they opened it, and confirm that key before
reaching it.

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
| [api.h](mpss-openssl/api.h) | Provider initialization, policy and storage-tier constants, discovery, errors, and key deletion by name or location |
| [interaction_handler.h](mpss-openssl/interaction_handler.h) | C callbacks for YubiKey PIN entry and touch notifications |
| [log.h](mpss-openssl/log.h) | The shared C logging API |
| [provider/](mpss-openssl/provider/) | Key management, signing, digests, codecs, and store implementation |

### Using the OpenSSL Provider

These usage fragments omit some error handling; check OpenSSL return values and release
resources on all paths. Register a statically linked provider with `OSSL_PROVIDER_add_builtin`.
For dynamic loading, make its shared library available on OpenSSL's provider search path.

#### Basic Key Generation and Signing

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

#### Opening Existing Keys and Public Key Extraction

Open `mpss:<key_name>` through `OSSL_STORE` with **`"provider=mpss"`** to select MPSS key
management. Supply `mpss_backend` to select a non-default backend. The result is an `EVP_PKEY`
referencing the stored key; ambiguous names are refused.

The remaining examples assume a live `libctx` with MPSS and the default provider loaded.

```cpp
#include <openssl/pem.h>
#include <openssl/store.h>

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
    if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
    {
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

#### Self-Signed Certificate Creation

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

#### Provider-Specific Parameters

**Settable parameters** (passed via `EVP_PKEY_CTX_set_params` during key generation):

| Parameter | Type | Required | Description |
|---|---|---|---|
| `mpss_key_name` | UTF-8 string | Yes | A persistent name, unique within the selected backend, containing 1-64 printable ASCII characters. The YubiKey backend reserves `"(available)"`. |
| `mpss_algorithm` | UTF-8 string | Yes | Algorithm suite, e.g., `"ecdsa_secp256r1_sha256"` |
| `mpss_backend` | UTF-8 string | No | Backend name; defaults to the selected backend. List names with `mpss_get_available_backends()` |
| `mpss_device_id` | UTF-8 string | No | Exact backend-specific device ID. For YubiKey, a decimal serial. An empty string requests automatic selection without the environment default; omission uses the default serial |
| `mpss_key_policy` | uint64 | No | `MPSS_KEY_POLICY_*` fields from `api.h`; defaults to `NONE`. The backend must enforce the requested policy |

**Gettable parameters** (queried via `EVP_PKEY_get_params` on an existing key):

| Parameter | Type | Description |
|---|---|---|
| `mpss_key_name` | UTF-8 string | The key's persistent name. |
| `mpss_algorithm` | UTF-8 string | The key's algorithm suite (canonical form). |
| `mpss_backend` | UTF-8 string | The backend that created or opened the key. |
| `mpss_device_id` | UTF-8 string | The device actually used, as a canonical decimal serial for YubiKey; empty for backends without device IDs. Read-only on an existing key |
| `is_hardware_backed` | int | The core `KeyInfo` boolean, exposed as `1` or `0`. See [Threat Model](#threat-model) for what it reports; on Windows only TPM keys report `1`. |
| `storage_tier` | int | The exact tier, as the number of the corresponding `mpss::StorageTier`. The numbers are fixed and only ever appended to, and `MPSS_STORAGE_TIER_*` in `mpss-openssl/api.h` names them; a value those constants do not name is a tier newer than the consumer's headers, so fall back to the two parameters that are answered for every tier. |
| `storage_description` | UTF-8 string | Human-readable description of the storage location (e.g., `"Keychain"`, `"YubiKey PIV"`). Intended for display; compare `storage_tier` rather than this string. |

The standard OpenSSL parameters `OSSL_PKEY_PARAM_GROUP_NAME`, `OSSL_PKEY_PARAM_BITS`, `OSSL_PKEY_PARAM_SECURITY_BITS`, `OSSL_PKEY_PARAM_MANDATORY_DIGEST`, and `OSSL_PKEY_PARAM_DEFAULT_DIGEST` are also supported.

`mpss_device_id` is also accepted by `OSSL_STORE_open_ex` and `OSSL_STORE_delete`.
Supply it with `mpss_backend` to select a particular device without changing process-wide defaults.
Retrieve the actual serial from a generated or opened key with `EVP_PKEY_get_utf8_string_param(pkey, "mpss_device_id", ...)`.
The returned device metadata remains associated with that key; a setter cannot retarget an existing `EVP_PKEY`.

#### Certificate Authority and Certificate Chain Creation

A complete end-to-end example of creating a CA certificate with an MPSS-backed key and signing end-entity certificates with it is shown in [tests/mpss_openssl_e2e_test.cpp](tests/mpss_openssl_e2e_test.cpp).

#### Secure Key Cleanup

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

mpss_key_location_t location{"yubikey", "my-old-key", "35489220"};
bool cleared_on_device = mpss_delete_key_at(&location);
```

For `mpss_delete_key_at`, a null device ID requests automatic selection without consulting the serial environment variable.
An explicitly selected device that cannot be reached is an error, not proof that the name is absent.

Do not use handles to deleted keys. Freeing an `EVP_PKEY` alone does not delete the stored key.
Deletion is irreversible but does not prevent verification of existing signatures or certificates.
MPSS does not provide key-name enumeration.

#### Loading a Key from a Key Reference PEM

For applications that load keys from files, use a **key reference PEM**.
The PEM body is a DER-encoded ASN.1 structure containing a format version, the resolved backend and key name, an optional device ID, and the expected public key as SubjectPublicKeyInfo (SPKI).
They contain no private key material, PIN, management key, or reader name.
The device ID is backend-specific: a YubiKey reference records its actual serial, while an operating-system key needs no device ID.

```
-----BEGIN MPSS KEY REFERENCE-----
... base64-encoded reference ...
-----END MPSS KEY REFERENCE-----
```

The encoder below produces the reference; applications should not construct its binary representation manually.
Encoding reads the key's public metadata and can fail if the backing device or storage is unavailable.
It does not request a proof-of-possession signature.

The version 1 ASN.1 schema is:

```asn1
MPSSKeyReference ::= SEQUENCE {
    version    INTEGER,                         -- must be 1
    backend    UTF8String,
    keyName    UTF8String,
    deviceId   [0] EXPLICIT UTF8String OPTIONAL,
    publicKey  SubjectPublicKeyInfo
}
```

OpenSSL's ASN.1 templates handle encoding and decoding; there is no MPSS-specific length header or reference-kind field in the file.
Backend and key names must contain 1-64 printable ASCII bytes; an optional device ID must contain 1-256 printable ASCII bytes and satisfy the selected backend's device-ID rules.
The decoded reference is limited to 4096 bytes and the PEM input to 8192 bytes.
The provider reads one PEM record at a time, counting any leading text toward the input limit and leaving subsequent records unread.
The decoder is synchronous and does not support resuming partially supplied input.
A record ending exactly at the limit must include its final LF newline.
Non-DER encodings, trailing data, extra fields, missing public keys, unsupported versions, and invalid public keys are rejected before opening a key.

A future format can introduce a new version and schema.
Readers supporting that version can validate older references with the older schema and convert their contents to the current in-memory representation.
Conversion must preserve device selection and expected-key constraints; it cannot invent new required information or silently discard constraints it does not understand.
Version 1 readers reject later versions rather than interpreting them as version 1.

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

A reference resolves only its recorded location and checks the public key before returning a handle.
Reading never creates a key, silently chooses another device, or replaces a mismatched expected key.
A reference-bound signing operation verifies the returned signature on the host against that expected key before reporting success.
This catches a device that reports the expected public key but produces a signature under a different key, without requesting a second signature.
Verification through such a handle also uses the expected key rather than whatever the backend holds under the name.
Loading itself does not add a signing challenge or proof-of-possession prompt; normal backend access may still require interaction.

Only versioned reference PEMs containing an expected public key are accepted.
Internal store locator messages use a separate ASN.1 structure and are rejected as PEM input.
Ordinary `mpss:` store URIs still support name-based loading and device-selection defaults; exporting a loaded key records its current location and public key.

**Trust and proof of possession.** Treat a reference as credential-selection configuration, not an authentication certificate.
Parsing it safely does not authorize an untrusted party to choose a local credential for the application.
Protect the file's integrity or retain the enrolled public key through an independently trusted channel, such as the application's enrollment database or a relying party.
An attacker able to replace the entire reference can replace its public key too; neither a self-signature nor a challenge verified against that substituted key recovers the original trust.

Public-key comparison checks reported identity, not current access to the private key.
If an application needs fresh proof of signing access, it should explicitly request a signature over an unpredictable, purpose-specific challenge and verify it against the independently trusted public key.
Ordinary signature verification establishes valid output; freshness additionally requires an unpredictable challenge or the application's existing authentication protocol.
Such a proof can require a PIN or touch, does not authenticate the reader or establish hardware provenance, and does not prevent relaying to the genuine signing key.
References are therefore not self-signed and loading them does not perform this challenge automatically.

### Errors and the OpenSSL Error Queue

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
    if (mpss_has_error())
    {
        fprintf(stderr, "delete failed: %s\n", mpss_get_error());
    }
    ERR_print_errors_fp(stderr);
}
```

The two channels are independent and thread-local. Clear the OpenSSL queue before an operation
whose errors you want to isolate. A non-empty queue alone does not indicate failure: it may
contain entries from recovered internal steps. See [Error Handling](#error-handling) for the
core last-error contract.

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
