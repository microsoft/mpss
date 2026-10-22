# List of Changes

## Version 2.1.1

- Fixed the shared OpenSSL provider on Windows when built with a CMake generator other than Visual Studio, such as Ninja, which vcpkg uses. The DLL did not export `OSSL_provider_init`, so OpenSSL could not load it, and a program that referenced `OSSL_provider_init` to register the provider failed to link. The DLL now exports it with every generator.
- Documented how to load the shared provider with `OSSL_PROVIDER_load`: by the library's full path, or by the name `mpss_openssl` on Windows or `libmpss_openssl` on Linux and macOS, with `_debug` appended for Debug builds, from OpenSSL's provider search path.
- Added the `win-ninja-x64-shared` preset, which builds the shared libraries with Ninja, as vcpkg does, and a test that loads the shared provider from its file.
