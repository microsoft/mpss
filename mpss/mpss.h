// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

namespace mpss {
    /**
    * @brief Creates a new key pair with the given name.
    * @param name The name of the key pair.
    * @return True if the key pair was created successfully, false otherwise.
    */
    bool create_key(std::string_view name);

    /**
    * @brief Deletes the key pair with the given name.
    * @param name The name of the key pair.
    * @return True if the key pair was deleted successfully, false otherwise.
    */
    bool delete_key(std::string_view name);

    /**
    * @brief Signs the given data with the key pair with the given name.
    * @param name The name of the key pair.
    * @param data The data to sign.
    * @return The signature if the data was signed successfully, an empty optional otherwise.
    */
    std::optional<std::string> sign(std::string_view name, std::string data);

    /**
    * @brief Verifies the given data with the key pair with the given name.
    * @param name The name of the key pair.
    * @param data The data to verify.
	* @param signature The signature to verify.
    * @return True if the data was verified successfully, false otherwise.
    */
    bool verify(std::string_view name, std::string data, std::string signature);

    /**
    * @brief Retrieves a verification-signing (public-private) key pair with the given name.
    * @param name The name of the key pair.
    * @param vk_out The verification key.
    * @param sk_out The signing key.
    * @return True if the key pair was retrieved successfully, false otherwise.
    * @note This function should not be used unless there is a special need to retrieve pre-existing keys.
    * Instead, the sign function should be used to sign data and the verify function should be used to verify signatures.
    */
    bool get_key(std::string_view name, std::string& vk_out, std::string& sk_out);

    /**
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred.
    */
    std::string get_error();
}