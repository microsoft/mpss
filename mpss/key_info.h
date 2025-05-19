// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>

namespace mpss {
    struct KeyInfo {
        KeyInfo(bool hardware_backed, const char *storage_description)
            : is_hardware_backed(hardware_backed), storage_description(storage_description)
        {}

        bool is_hardware_backed;
        const char *storage_description;
    };
} // namespace mpss
