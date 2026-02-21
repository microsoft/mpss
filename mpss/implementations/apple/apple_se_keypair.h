// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/implementations/apple/apple_keypair.h"

namespace mpss::impl::os
{

/**
 * @brief Key pair implementation that uses the Apple Secure Enclave for storage and operations.
 *
 * This class provides functionality to manage cryptographic key pairs stored in the Apple Secure Enclave.
 * It implements key deletion, signing, verification, and public key extraction using the Apple Secure Enclave APIs.
 */
class AppleSEKeyPair : public AppleKeyPairBase
{
  public:
    AppleSEKeyPair(std::string_view name, Algorithm algorithm);
    ~AppleSEKeyPair() override;

  protected:
    bool do_delete_key() override;
    std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const override;
    bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const override;
    std::size_t do_extract_key(std::span<std::byte> public_key) const override;
    void do_release_key() override;
};

} // namespace mpss::impl::os
