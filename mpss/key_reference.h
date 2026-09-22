// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace mpss
{

/**
 * @brief Identifies a key by backend, name, and optional device ID.
 *
 * Leave device_id unset to let the backend select a device automatically.
 * Calls using KeyLocation do not use MPSS_YUBIKEY_SERIAL.
 */
struct KeyLocation
{
    std::string backend_name;
    std::string name;
    std::optional<std::string> device_id;
};

/** @brief A location bound to the algorithm and public bytes returned by KeyPair::extract_key. */
struct KeyReference
{
    KeyLocation location;
    Algorithm algorithm{Algorithm::unsupported};
    std::vector<std::byte> public_key;
};

} // namespace mpss
