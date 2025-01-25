// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

namespace mpss {
	enum class SignatureAlgorithm {
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA512
	};

    /**
    * @brief Creates a new key pair with the given name.
    * @param name The name of the key pair.
    * @return True if the key pair was created successfully, false otherwise.
    */
    bool create_key(std::string_view name, SignatureAlgorithm algorithm);

    /**
    * @brief Deletes the key pair with the given name.
    * @param name The name of the key pair.
    * @return True if the key pair was deleted successfully, false otherwise.
    */
    bool delete_key(std::string_view name);

    /**
    * @brief Signs the given data with the key pair with the given name.
    * @param name The name of the key pair.
    * @param data The hash to sign.
	* @param algorithm The signature algorithm to use.
    * @return The signature if the data was signed successfully, an empty optional otherwise.
	* @note The data needs to be hashed before signing. The hash algorithm should match the given signature algorithm.
    */
    std::optional<std::string> sign(std::string_view name, std::string_view hash, SignatureAlgorithm algorithm);

    /**
    * @brief Verifies the given data with the key pair with the given name.
    * @param name The name of the key pair.
    * @param hash The hash to verify.
	* @param signature The signature to verify.
	* @param algorithm The signature algorithm to use.
    * @return True if the data was verified successfully, false otherwise.
    */
    bool verify(std::string_view name, std::string_view hash, std::string_view signature, SignatureAlgorithm algorithm);

    /**
    * @brief Retrieves a verification (public) key with the given name.
    * @param name The name of the key pair.
    * @param vk_out The verification key.
    * @return True if the verification key retrieved successfully, false otherwise.
    */
    bool get_key(std::string_view name, SignatureAlgorithm algorithm, std::string& vk_out);

    /**
    * @brief Determines whether the given signature algorithm is supported in the safe storage system.
    * @param algorithm The signature algorithm to verify
	* @return True if the signature algorithm is supported in safe storage, false otherwise.
    */
	bool is_safe_storage_supported(SignatureAlgorithm algorithm);

    /**
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred.
    */
    std::string get_error();
}