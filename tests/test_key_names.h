// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// Test key names are made unique to the running process, so that two test binaries executing at the
// same time -- on one machine, or against one attached device -- cannot collide on a key name and
// fail each other's tests.
//
// The process id is used rather than a random value because the operating system recycles it. A run
// that is killed before its cleanup runs leaves keys behind, and MPSS cannot enumerate keys, so the
// only way a stranded key is ever reclaimed is a later run that receives the same id and deletes it
// by name on the way in. A random suffix would strand it permanently, which matters most on a
// YubiKey, where there are only 20 usable slots.

#include <cstddef>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace mpss::tests
{
inline int current_process_id() noexcept
{
#ifdef _WIN32
    return ::_getpid();
#else
    return static_cast<int>(::getpid());
#endif
}

/**
 * @brief Prefixes a key name with the current process id.
 */
inline std::string test_key_name(std::string_view base)
{
    return "p" + std::to_string(current_process_id()) + "_" + std::string{base};
}

/**
 * @brief Builds a process-unique key name of exactly `length` characters.
 *
 * For the tests that exercise the maximum permitted key name length, where appending to the name
 * would change what is being tested. The process id occupies the front and `fill` pads the rest, so
 * callers can still vary the trailing characters. Falls back to plain padding if the id does not fit.
 */
inline std::string test_key_name_of_length(std::size_t length, char fill = 'k')
{
    std::string name = "p" + std::to_string(current_process_id()) + "_";
    if (name.size() > length)
    {
        name.clear();
    }
    name.append(length - name.size(), fill);
    return name;
}
} // namespace mpss::tests
