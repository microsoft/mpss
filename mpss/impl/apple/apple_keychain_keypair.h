// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/apple/apple_keypair.h"
#include <cstdint>

namespace mpss::impl::os
{

/**
 * @brief Key pair implementation that uses the Apple Keychain for storage and operations.
 *
 * This class provides functionality to manage cryptographic key pairs stored in the Apple Keychain.
 * It implements key deletion, signing, verification, and public key extraction using the Apple Keychain APIs.
 */
class AppleKeychainKeyPair : public AppleKeyPairBase
{
  public:
    /**
     * @brief Constructs a handle to a key the Keychain holds.
     * @param name The key name.
     * @param algorithm The signature algorithm.
     * @param generation The hold this handle took on the cached key.
     * @param storage_tier Where the key store reported holding this key, read from the key itself
     * rather than from what creation asked for.
     */
    AppleKeychainKeyPair(std::string_view name, Algorithm algorithm, std::uint64_t generation,
                         StorageTier storage_tier);
    ~AppleKeychainKeyPair() override;

  protected:
    bool do_delete_key() override;
    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;
    [[nodiscard]]
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;
    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;
    bool do_release_key() override;
};

} // namespace mpss::impl::os
