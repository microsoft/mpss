// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace mpss::tests
{

int run_all_tests(int argc, char *argv[]);

/** @brief The connected YubiKeys listed in MPSS_TEST_YUBIKEYS, in listed order: the only ones tests may modify. */
[[nodiscard]]
std::vector<std::uint32_t> test_yubikeys();

/** @brief The one of test_yubikeys() that MPSS_YUBIKEY_SERIAL selects, so name-based calls reach it too. */
[[nodiscard]]
std::optional<std::uint32_t> test_yubikey_serial();

} // namespace mpss::tests
