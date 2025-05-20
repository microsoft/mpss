// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>

namespace mpss {
    /**
     * @brief Structure to hold information about a key.
     */
    struct KeyInfo {
        KeyInfo(bool hardware_backed, const char *storage_description)
            : is_hardware_backed(hardware_backed), storage_description(storage_description)
        {}

        /**
         * @brief Indicates if the key is backed by hardware
         */
        bool is_hardware_backed;

        /**
         * @brief Description of the storage where the key is stored.
         */
        const char *storage_description;
    };
} // namespace mpss
