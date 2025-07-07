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
| Android | [StrongBox](https://developer.android.com/privacy-and-security/keystore) if available |

## Compiling for different platforms

MPSS API depends on [Microsoft GSL](https://GitHub.com/Microsoft/GSL) and the library uses [GoogleTest](https://GitHub.com/Google/GoogleTest) for testing.
The OpenSSL provider naturally requires [OpenSSL](https://GitHub.com/openssl/openssl).
MPSS provides the relevant dependencies file ([vcpkg.json](vcpkg.json)) for [vcpkg](https://GitHub.com/Microsoft/vcpkg).

### Windows

When configuring with CMake, simply provide the path to the `vcpkg` toolchain file, as follows:

```cmd
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake
```

### macOS

As for Windows, when configuring with CMake, you only need to provide the path to the `vcpkg` toolchain file:

```bash
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
```

### iOS
Generating an Xcode project is recommended for iOS. After generating the project, it can simply be added to a different Xcode project as a Framework. Another benefit of generating an Xcode project is that you don't have to worry about targeting either the iPhone Simulator or a real iPhone. Xcode will take care of this.
The command to generate an Xcode project is the following:

```bash
cmake -S . -B build -GXcode -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_DEPLOYMENT_TARGET=$IPHONE_SDK_VERSION -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO -DCMAKE_IOS_INSTALL_COMBINED=YES
```

In order to find out what iPhone SDKs are installed, you can run the following command:

```bash
xcodebuild -showsdks
```

This will show all installed SDKs. If the SDK appears as `iOS 18.4`, for example, you would need to specify `-DCMAKE_OSX_DEPLOYMENT_TARGET=18.4`.


### Android
Generate Ninja build files for cross compiling to the x64 Android simulator. The vcpkg toolchain file is specified to satisfy build dependencies of MPSS.

```cmd
cmake -S . -B buildX64 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=%ANDROID_API_VERSION% -DCMAKE_ANDROID_ARCH_ABI=x86_64 -GNinja -DCMAKE_MAKE_PROGRAM=%NINJA_ROOT%\ninja.exe -DCMAKE_ANDROID_NDK=%ANDROID_NDK_HOME%
```

Generate Ninja build files for cross compiling to Arm64.

```cmd
cmake -S . -B buildArm -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=%ANDROID_API_VERSION% -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a -GNinja -DCMAKE_MAKE_PROGRAM=%NINJA_ROOT%\ninja.exe -DCMAKE_ANDROID_NDK=%ANDROID_NDK_HOME%
```

**Note**: You will need to also set the following environment variables:
| Variable | Value |
| -------- | ----- |
| ANDROID_HOME | Path to your Android SDK installation |
| ANDROID_NDK_HOME | Path to your Android NDK installation |
| JAVA_HOME | Path to your Java SDK installation |
| JAVA_COMPILER | Path to the Java compiler |

**Note**: `CMAKE_SYSTEM_NAME` is used to build a full path to `android.jar`, which needs to be linked against when generating the MPSS jar file. **Make sure this path exists**. The full path to `android.jar` is composed like this:
```cmd
%ANDROID_HOME%\platforms\android-%CMAKE_SYSTEM_NAME%\android.jar
```
