// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {
bool MPSS_OpenExistingKey(const char *keyName, int *bitSize);
bool MPSS_CreateKey(const char *keyName, int bitSize);
bool MPSS_SignHash(
    const char *keyName,
    int signatureType,
    const std::uint8_t *hash,
    std::size_t hashSize,
    std::uint8_t *signature,
    std::size_t *signatureSize);
bool MPSS_VerifySignature(
    const char *keyName,
    int signatureType,
    const std::uint8_t *hash,
    std::size_t hashSize,
    const std::uint8_t *signature,
    std::size_t signatureSize);
bool MPSS_VerifyStandaloneSignature(
    int signatureType,
    const std::uint8_t *hash,
    std::size_t hashSize,
    const std::uint8_t *publicKey,
    std::size_t publicKeySize,
    const std::uint8_t *signature,
    std::size_t signatureSize);
bool MPSS_GetPublicKey(const char *keyName, std::uint8_t *pk, std::size_t *pkSize);
bool MPSS_DeleteKey(const char *keyName);
void MPSS_RemoveKey(const char *keyName);
const char *MPSS_GetLastError();
}
