// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include <array>
#include <cstdint>

namespace mpss
{

/**
 * @brief Where a key is held, and therefore what holding it is worth.
 *
 * A backend decides only which of these a key obtained. Whether that counts as hardware backing,
 * and how it is described, are answered once in @ref storage_tiers rather than at each place a key
 * pair is constructed.
 *
 * The numbers are written out because the OpenSSL provider reports them as the "storage_tier"
 * parameter, where a consumer built against a different version of this header reads them. Append
 * new tiers at the end and give them the next number; never renumber a tier and never give a
 * retired tier's number to a new one, or an old consumer will read a tier as a different tier.
 *
 * They are names, not a rank. Compare a tier for equality; never order it. The numbers run in
 * increasing protection within a platform, which makes `tier >= windows_tpm` look right and pass a
 * test on one platform, and then accept apple_keychain and android_software as stronger than a TPM.
 * What ranks tiers against each other is @ref StorageTierInfo::is_hardware_backed.
 */
enum class StorageTier : std::uint8_t
{
    unknown = 0,                     /**< The tier could not be established. */
    windows_software = 1,            /**< Windows software key storage. */
    windows_vbs = 2,                 /**< Windows Virtualization Based Security. */
    windows_tpm = 3,                 /**< Windows TPM-backed key storage. */
    apple_keychain = 4,              /**< Apple Keychain, without the Secure Enclave. */
    apple_secure_enclave = 5,        /**< Apple Secure Enclave. */
    android_software = 6,            /**< Android key store, software security level. */
    android_unknown_secure = 7,      /**< Android secure hardware of a level the platform did not name. */
    android_trusted_environment = 8, /**< Android Trusted Environment. */
    android_strongbox = 9,           /**< Android StrongBox. */
    yubikey_piv = 10,                /**< YubiKey PIV secure element. */

    count /**< Not a tier. The number of them, so the table can be checked against this enum. */
};

/**
 * @brief What a storage tier is, as reported through @ref KeyInfo.
 */
struct StorageTierInfo
{
    StorageTier tier;
    bool is_hardware_backed;
    const char *description;
};

/**
 * @brief Every storage tier, and the answers it gives.
 *
 * `is_hardware_backed` is true when the private key is held outside the operating system's reach,
 * in storage the platform vendor classifies as secure hardware. Virtualization Based Security is
 * false despite not being exportable: its isolation rests on the hypervisor, and what protects the
 * key at rest depends on Secure Boot and on a TPM being present, neither of which MPSS can
 * establish. A tier is described even when it is not hardware backing, so a caller can tell the
 * false answers apart.
 */
inline constexpr std::array<StorageTierInfo, 11> storage_tiers = {
    StorageTierInfo{StorageTier::unknown, false, "Unknown"},
    StorageTierInfo{StorageTier::windows_software, false, "Software Protection"},
    StorageTierInfo{StorageTier::windows_vbs, false, "Virtualization Based Security"},
    StorageTierInfo{StorageTier::windows_tpm, true, "TPM Protection"},
    StorageTierInfo{StorageTier::apple_keychain, false, "Keychain"},
    StorageTierInfo{StorageTier::apple_secure_enclave, true, "Secure Enclave"},
    StorageTierInfo{StorageTier::android_software, false, "Software"},
    StorageTierInfo{StorageTier::android_unknown_secure, true, "Unknown Secure"},
    StorageTierInfo{StorageTier::android_trusted_environment, true, "Trusted Environment"},
    StorageTierInfo{StorageTier::android_strongbox, true, "StrongBox"},
    StorageTierInfo{StorageTier::yubikey_piv, true, "YubiKey PIV"},
};

/**
 * @brief What a storage tier reports.
 * @param tier The tier a key obtained.
 * @return The row @ref storage_tiers holds for it, or the unknown row if it holds none.
 */
[[nodiscard]]
inline constexpr StorageTierInfo get_storage_tier_info(StorageTier tier) noexcept
{
    for (const StorageTierInfo &info : storage_tiers)
    {
        if (info.tier == tier)
        {
            return info;
        }
    }

    // A tier with no row is a tier this build does not know, which is not something to report as
    // protection. Spelled out rather than taken from the table, so that reordering the rows cannot
    // turn the answer for an unknown tier into hardware backing.
    return StorageTierInfo{StorageTier::unknown, false, "Unknown"};
}

// Every tier has a row, and every row answers for the tier it names. A tier added to the enum
// without a row fails to compile here rather than reporting an unknown protection at run time.
static_assert(storage_tiers.size() == static_cast<std::size_t>(StorageTier::count),
              "storage_tiers must hold exactly one row per StorageTier");
static_assert(
    [] {
        for (std::size_t i = 0; i < storage_tiers.size(); ++i)
        {
            const auto tier = static_cast<StorageTier>(i);
            if (storage_tiers.at(i).tier != tier || get_storage_tier_info(tier).tier != tier)
            {
                return false;
            }
        }
        return true;
    }(),
    "storage_tiers must be indexed by StorageTier and resolve to the tier asked for");

} // namespace mpss
