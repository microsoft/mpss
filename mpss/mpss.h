// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

namespace mpss {
    /**
	* @brief The supported signature algorithms.
    */
	enum class SignatureAlgorithm {
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA512
	};

    /**
	* @brief The handle to a key pair in the safe storage system.
    */
    class KeyPairHandle;

    /**
    * @brief Creates a new key pair with the given name.
    * @param name The name of the key pair.
	* @param algorithm The signature algorithm to use.
    * @return Key pair handle if the key pair was created successfully, an empty optional otherwise.
    */
    std::optional<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm);

    /**
	* @brief Opens the key pair with the given name.
	* @param name The name of the key pair to open.
	* @return Key pair handle if the key pair was opened successfully, an empty optional otherwise.
    */
	std::optional<KeyPairHandle> open_key(std::string_view name);

    /**
    * @brief Deletes the key pair with the given name.
	* @param handle The handle to the key pair.
    * @return True if the key pair was deleted successfully, false otherwise.
	* @note After this function returns successfully, the key pair handle is no longer valid.
    */
    bool delete_key(KeyPairHandle handle);

    /**
    * @brief Signs the given data with the key pair with the given name.
	* @param handle The handle to the key pair.
    * @param data The hash to sign.
	* @param algorithm The signature algorithm to use.
    * @return The signature if the data was signed successfully, an empty optional otherwise.
	* @note The data needs to be hashed before signing. The hash algorithm should match the given signature algorithm.
    */
    std::optional<std::string> sign(KeyPairHandle handle, std::string_view hash, SignatureAlgorithm algorithm);

    /**
    * @brief Verifies the given data with the key pair with the given name.
	* @param handle The handle to the key pair.
    * @param hash The hash to verify.
	* @param signature The signature to verify.
	* @param algorithm The signature algorithm to use.
    * @return True if the data was verified successfully, false otherwise.
    */
    bool verify(KeyPairHandle handle, std::string_view hash, std::string_view signature, SignatureAlgorithm algorithm);

    /**
    * @brief Retrieves a verification (public) key with the given name.
	* @param handle The handle to the key pair.
    * @param vk_out The verification key.
    * @return True if the verification key retrieved successfully, false otherwise.
    */
    bool get_key(KeyPairHandle handle, SignatureAlgorithm algorithm, std::string& vk_out);

    /**
    * @brief Determines whether the given signature algorithm is supported in the safe storage system.
    * @param algorithm The signature algorithm to verify
	* @return True if the signature algorithm is supported in safe storage, false otherwise.
    */
	bool is_safe_storage_supported(SignatureAlgorithm algorithm);

    /**
	* @brief Releases the key pair handle.
	* @note This function should be called when the key pair handle is no longer needed.
    */
	void release_key(KeyPairHandle handle);

    /**
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred.
    */
    std::string get_error();



    class KeyPairHandle {
    public:
        KeyPairHandle() = delete;

    protected:
		std::string name_;
		SignatureAlgorithm algorithm_;
        std::size_t hash_size_;

        KeyPairHandle(std::string_view name, SignatureAlgorithm algorithm);
    };
}
