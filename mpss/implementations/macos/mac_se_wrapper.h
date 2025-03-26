// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <cstddef>

extern "C"
{
    bool MPSS_SecureEnclaveIsSupported();
    bool MPSS_OpenExistingKey(const char* keyName);
}
