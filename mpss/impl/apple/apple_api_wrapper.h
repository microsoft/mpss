// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/apple/apple_result.h"
#include <cstddef>
#include <cstdint>

extern "C"
{
    // On success takes a hold on the cached key and reports the generation it was taken on, which
    // must be handed back to MPSS_RemoveKey so a release cannot be charged against a later key of
    // the same name.
    std::int32_t MPSS_OpenExistingKey(const char *keyName, int *bitSize, std::uint64_t *generation);
    bool MPSS_CreateKey(const char *keyName, int bitSize, std::uint64_t *generation);
    bool MPSS_SignHash(const char *keyName, int signatureType, const std::uint8_t *hash, std::size_t hashSize,
                       std::uint8_t *signature, std::size_t *signatureSize);
    std::int32_t MPSS_VerifySignature(const char *keyName, int signatureType, const std::uint8_t *hash,
                                      std::size_t hashSize, const std::uint8_t *signature, std::size_t signatureSize);
    std::int32_t MPSS_VerifyStandaloneSignature(int signatureType, const std::uint8_t *hash, std::size_t hashSize,
                                                const std::uint8_t *publicKey, std::size_t publicKeySize,
                                                const std::uint8_t *signature, std::size_t signatureSize);
    bool MPSS_GetPublicKey(const char *keyName, std::uint8_t *pk, std::size_t *pkSize);

    // Whether the Keychain tier holds this name, without loading the key or consulting the
    // in-process cache. Lets the caller detect a name held in more than one tier.
    std::int32_t MPSS_KeychainKeyExists(const char *keyName);

    bool MPSS_DeleteKey(const char *keyName);
    void MPSS_RemoveKey(const char *keyName, std::uint64_t generation);
    std::size_t MPSS_GetLastError(char *error, std::size_t errorSize);
}
