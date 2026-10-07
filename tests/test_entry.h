// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <optional>

namespace mpss::tests
{

int run_all_tests(int argc, char *argv[]);

/** @brief The connected YubiKey that MPSS_YUBIKEY_SERIAL selects, which is the only one tests may modify. */
[[nodiscard]]
std::optional<std::uint32_t> test_yubikey_serial();

/** @brief Whether the caller set MPSS_YUBIKEY_SERIAL, which keeps tests off every other YubiKey. */
[[nodiscard]]
bool yubikey_serial_set_by_caller();

} // namespace mpss::tests
