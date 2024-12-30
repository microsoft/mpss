// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <string>
#include <optional>

namespace mpss {
    /**
    * @brief Creates a new key pair with the given name.
    * @param name The name of the key pair.
    * @return True if the key pair was created successfully, false otherwise.
    */
    bool create_key(const std::string& name);

    /**
    * @brief Deletes the key pair with the given name.
    * @param name The name of the key pair.
    * @return True if the key pair was deleted successfully, false otherwise.
    */
    bool delete_key(const std::string& name);

    /**
    * @brief Signs the given data with the key pair with the given name.
    * @param name The name of the key pair.
    * @param data The data to sign.
    * @return The signature if the data was signed successfully, an empty optional otherwise.
    */
    std::optional<std::string> sign(const std::string& name, const std::string& data);

    /**
    * @brief Verifies the given data with the key pair with the given name.
    * @param name The name of the key pair.
    * @param data The data to verify.
	* @param signature The signature to verify.
    * @return True if the data was verified successfully, false otherwise.
    */
    bool verify(const std::string& name, const std::string& data, const std::string& signature);

    /**
    * @brief Stores a verification-signing (public-private) key pair with the given name.
    * @param name The name of the key pair.
    * @param vk The verification key.
    * @param sk The signing key.
    * @return True if the key pair was stored successfully, false otherwise.
    * @note This function should not be used unless there is a special need to store pre-existing keys.
    * Instead, the create_key function should be used to generate new key pairs.
    */
    bool set_key(const std::string& name, const std::string& vk, const std::string& sk);

    /**
    * @brief Retrieves a verification-signing (public-private) key pair with the given name.
    * @param name The name of the key pair.
    * @param vk_out The verification key.
    * @param sk_out The signing key.
    * @return True if the key pair was retrieved successfully, false otherwise.
    * @note This function should not be used unless there is a special need to retrieve pre-existing keys.
    * Instead, the sign function should be used to sign data and the verify function should be used to verify signatures.
    */
    bool get_key(const std::string& name, std::string& vk_out, std::string& sk_out);

    /**
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred.
    */
    const std::string& get_error();
}