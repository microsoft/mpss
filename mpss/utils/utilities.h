// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>
#include <gsl/gsl>

#include "mpss/mpss.h"

namespace mpss {
    namespace utils {
        // Convert a long to a hex string
        std::string to_hex(long value);

        // Get the last error string that occurred
        std::string get_error();

        // Set the last error string that occurred
        void set_error(std::string error);

		// Verify the length of the hash based on the signature algorithm
		bool verify_hash_length(gsl::span<std::byte> hash, SignatureAlgorithm algorithm);

        // Throw an exception if the argument is null
		void throw_if_null(const void* arg, std::string_view name);
    }
}
