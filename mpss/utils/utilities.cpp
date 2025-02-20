// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace {
    thread_local std::string _last_error;
}

namespace mpss {
    namespace utils {
        // Convert a long to a hex string
        std::string to_hex(long value)
        {
            std::stringstream ss;
            ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
            return ss.str();
        }

        std::string get_error()
        {
            return _last_error;
        }

        void set_error(std::string error)
        {
            _last_error = std::move(error);
        }

        bool verify_hash_length(gsl::span<std::byte> hash, SignatureAlgorithm algorithm)
        {
            switch (algorithm) {
            case SignatureAlgorithm::ECDSA_P256_SHA256:
                return hash.size() == 32;
            case SignatureAlgorithm::ECDSA_P384_SHA384:
                return hash.size() == 48;
            case SignatureAlgorithm::ECDSA_P521_SHA512:
                return hash.size() == 64;
            default:
                throw new std::invalid_argument("Unsupported algorithm");
            }
        }

		void throw_if_null(const void* arg, std::string_view name)
		{
			if (arg == nullptr) {
				throw new std::invalid_argument(std::string(name) + " cannot be null");
			}
		}
    }
}
