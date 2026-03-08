// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"

#ifdef __cplusplus
namespace mpss
{

/**
 * @brief Structure to hold information about a key.
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)
struct MPSS_DECOR KeyInfo
{
    KeyInfo(bool hardware_backed, const char *storage_description)
        : is_hardware_backed{hardware_backed}, storage_description{storage_description}
    {
    }

    /**
     * @brief Indicates if the key is backed by hardware
     */
    const bool is_hardware_backed;

    /**
     * @brief Description of the storage where the key is stored.
     */
    const char *storage_description;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)

} // namespace mpss
#endif // __cplusplus
