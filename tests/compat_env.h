// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// Platform-compatible wrappers for setenv / unsetenv.
// MSVC does not provide the POSIX versions; _putenv_s is the equivalent.

#ifdef _WIN32
#include <cstdlib>

inline int setenv(const char *name, const char *value, int /*overwrite*/) noexcept
{
    return _putenv_s(name, value);
}

inline int unsetenv(const char *name) noexcept
{
    return _putenv_s(name, "");
}
#endif // _WIN32
