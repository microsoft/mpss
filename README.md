# mpss is a multi-platform secret storage library

## Compiling for different platforms

### Windows
TODO

### MacOS
TODO

### iOS
1. Generate Xcode project

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
| JAVA_HOME | Path to your Java installation |
| JAVA_COMPILER | Path to the Java compiler |

**Note**: `CMAKE_SYSTEM_NAME` is used to build a full path to `android.jar`, which needs to be linked against when generating the MPSS jar file. Make sure this path exists. The full path to `android.jar` is composed like this:
```
<ANDROID_HOME>\platforms\android-<CMAKE_SYSTEM_NAME>\android.jar
```
