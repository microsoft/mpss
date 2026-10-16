// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <stdint.h>

#define MPSS_APPLE_RESULT_OPERATIONAL_ERROR ((int32_t)-1)
#define MPSS_APPLE_RESULT_EXPECTED_NEGATIVE ((int32_t)0)
#define MPSS_APPLE_RESULT_SUCCESS ((int32_t)1)

// Where the key store put a key, as reported by MPSS_CreateKey and MPSS_OpenExistingKey. Shared so
// that the side reading the key and the side naming the tier cannot drift apart.
#define MPSS_APPLE_KEY_LOCATION_INDETERMINATE ((int32_t)0)
#define MPSS_APPLE_KEY_LOCATION_SOFTWARE ((int32_t)1)
#define MPSS_APPLE_KEY_LOCATION_SECURE_ENCLAVE ((int32_t)2)
