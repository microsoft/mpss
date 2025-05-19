// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {
bool MPSS_SE_SecureEnclaveIsSupported();
bool MPSS_SE_CreateKey(const char *keyName);
bool MPSS_SE_OpenExistingKey(const char *keyName);
void MPSS_SE_RemoveExistingKey(const char *keyName);
void MPSS_SE_CloseKey(const char *keyName);
bool MPSS_SE_Sign(
    const char *keyName,
    const std::uint8_t *hash,
    std::size_t hashSize,
    std::uint8_t *sig,
    std::size_t *sigSize);
bool MPSS_SE_VerifySignature(
    const char *keyName,
    const std::uint8_t *hash,
    std::size_t hashSize,
    const std::uint8_t *sig,
    std::size_t sigSize);
bool MPSS_SE_VerifyStandaloneSignature(
    const std::uint8_t *publicKey,
    std::size_t publicKeySize,
    const std::uint8_t *hash,
    std::size_t hashSize,
    const std::uint8_t *sig,
    std::size_t sigSize);
bool MPSS_SE_GetPublicKey(const char *keyName, std::uint8_t *publicKey, std::size_t *publicKeySize);
std::size_t MPSS_SE_GetLastError(char *error, std::size_t errorSize);
}
