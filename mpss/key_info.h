// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"

#ifdef __cplusplus
#include "mpss/storage_tier.h"

namespace mpss
{

/**
 * @brief Structure to hold information about a key.
 *
 * A key pair reports one thing about where its key lives, and the rest follows from it: the tier
 * is what a backend establishes, and both fields after it are what @ref storage_tiers says that
 * tier reports. Constructing this from a tier is the only way to fill it, so the three cannot
 * disagree.
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members,*-non-private-member-variables-in-classes)
struct MPSS_DECOR KeyInfo
{
    explicit KeyInfo(StorageTier tier)
        : storage_tier{tier}, is_hardware_backed{get_storage_tier_info(tier).is_hardware_backed},
          storage_description{get_storage_tier_info(tier).description}
    {
    }

    /**
     * @brief Where the key is held. What a backend established, and what the two fields below are
     * derived from. The refinement for a caller whose bar is stricter than the flag.
     */
    const StorageTier storage_tier;

    /**
     * @brief Indicates if the key is backed by hardware
     *
     * The answer for a caller deciding whether to trust this key with a credential. A coarse one:
     * read @ref storage_tier when the difference between two tiers that both answer here matters.
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
