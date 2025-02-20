// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include "crypto_params.h"

namespace mpss {
    namespace impl {
        namespace utils {
            const crypto_params& GetCryptoParams(SignatureAlgorithm algorithm);

            void set_error(SECURITY_STATUS status, std::string error);
        }
    }
}
