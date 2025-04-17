# MPSS

Modern operating systems provide various methods for safeguarding private cryptographic keys through hardware. MPSS is a multi-platform secret storage library that offers a unified API, allowing users to store cryptographic keys securely without worrying about the specific APIs used by different operating systems.

MPSS uses the following technologies in the different platforms:

| Platform | API |
|----------|-----|
| Windows | VBS if available, TPM backed keys otherwise |
| MacOS / iOS | Secure Enclave if available, Keychain otherwise  |
| Android | StrongBox if available |

## Compiling for different platforms

MPSS depends on GSL and Google Test for testing. The easiest way to provide these dependencies is through `vcpkg`.

### Windows

You will only need to provide the path to the `vcpkg` toolchain file.

```
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg dir>\scripts\buildsystems\vcpkg.cmake
```

### MacOS
Same as above, you only need to provide the path to the `vcpkg` toolchain file.

```
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg dir>/scripts/buildsystems/vcpkg.cmake
```

### iOS
Generating an Xcode project is recommended for iOS. After generating the project, it can simply be added to a different Xcode project as a Framework. Another benefit of generating an Xcode project is that you don't have to worry about targeting either the iPhone Simulator or a real iPhone. Xcode will take care of this.
The command to generate an Xcode project is the following:

```
cmake -S . -B build -GXcode -DCMAKE_TOOLCHAIN_FILE=<vcpkg dir>/scripts/buildsystems/vcpkg.cmake -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_DEPLOYMENT_TARGET=<iPhone SDK Version> -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO -DCMAKE_IOS_INSTALL_COMBINED=YES
```

In order to find out what iPhone SDKs are installed, you can run the following command:

```
xcodebuild -showsdks
```

This will show all installed SDKs. If the SDK appears as `iOS 18.4`, for example, you would need to specify `-DCMAKE_OSX_DEPLOYMENT_TARGET=18.4`.


### Android
Generate Ninja build files for cross compiling to the x64 Android simulator. The vcpkg toolchain file is specified to satisfy build dependencies of MPSS.

```
cmake -S . -B buildX64 -DCMAKE_TOOLCHAIN_FILE=<vcpkg dir>\scripts\buildsystems\vcpkg.cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=<Android API version> -DCMAKE_ANDROID_ARCH_ABI=x86_64  -GNinja -DCMAKE_MAKE_PROGRAM=<Ninja dir>\ninja.exe -DCMAKE_ANDROID_NDK=<Android NDK dir>
```

Generate Ninja build files for cross compiling to Arm64.

```
cmake -S . -B buildArm -DCMAKE_TOOLCHAIN_FILE=<vcpkg dir>\scripts\buildsystems\vcpkg.cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=<Android API version> -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a  -GNinja -DCMAKE_MAKE_PROGRAM=<Ninja dir>\ninja.exe -DCMAKE_ANDROID_NDK=<Android NDK dir>
```

**Note**: You will need to also set the following environment variables:
| Variable | Value |
| -------- | ----- |
| ANDROID_HOME | Path to your Android SDK installation |
| ANDROID_NDK_HOME | Path to your Android NDK installation |
| JAVA_HOME | Path to your Java SDK installation |
| JAVA_COMPILER | Path to the Java compiler |

**Note**: `CMAKE_SYSTEM_NAME` is used to build a full path to `android.jar`, which needs to be linked against when generating the MPSS jar file. **Make sure this path exists**. The full path to `android.jar` is composed like this:
```
<ANDROID_HOME>\platforms\android-<CMAKE_SYSTEM_NAME>\android.jar
```
