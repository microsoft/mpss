// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <cstddef>

extern "C"
{
    bool OpenExistingKeyMacOS(const char *keyName, int *bitSize);
    bool CreateKeyMacOS(const char *keyName, int bitSize);
    bool SignHashMacOS(const char *keyName, int signatureType, const std::uint8_t *hash, std::size_t hashSize, std::uint8_t **signature, std::size_t *signatureSize);
    bool VerifySignatureMacOS(const char *keyName, int signatureType, const std::uint8_t *hash, std::size_t hashSize, const std::uint8_t *signature, std::size_t signatureSize);
    bool DeleteKeyMacOS(const char *keyName);
    void RemoveKeyMacOS(const char *keyName);
}
