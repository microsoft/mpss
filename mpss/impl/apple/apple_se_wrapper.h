// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/impl/apple/apple_result.h"
#include <cstddef>
#include <cstdint>

extern "C"
{
    bool MPSS_SE_SecureEnclaveIsSupported();
    bool MPSS_SE_CreateKey(const char *keyName, bool requireUserPresence, std::uint64_t *generation);
    // On success takes a hold on the cached key and reports the generation it was taken on, which
    // must be handed back to MPSS_SE_CloseKey so a release cannot be charged against a later key
    // of the same name.
    std::int32_t MPSS_SE_OpenExistingKey(const char *keyName, std::uint64_t *generation);
    bool MPSS_SE_RemoveExistingKey(const char *keyName);
    void MPSS_SE_CloseKey(const char *keyName, std::uint64_t generation);
    bool MPSS_SE_Sign(const char *keyName, const std::uint8_t *hash, std::size_t hashSize, std::uint8_t *sig,
                      std::size_t *sigSize);
    std::int32_t MPSS_SE_VerifySignature(const char *keyName, const std::uint8_t *hash, std::size_t hashSize,
                                         const std::uint8_t *sig, std::size_t sigSize);
    std::int32_t MPSS_SE_VerifyStandaloneSignature(const std::uint8_t *publicKey, std::size_t publicKeySize,
                                                   const std::uint8_t *hash, std::size_t hashSize,
                                                   const std::uint8_t *sig, std::size_t sigSize);
    bool MPSS_SE_GetPublicKey(const char *keyName, std::uint8_t *publicKey, std::size_t *publicKeySize);
    std::size_t MPSS_SE_GetLastError(char *error, std::size_t errorSize);
}
