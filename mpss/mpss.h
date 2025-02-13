// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <memory>

namespace mpss {
    /**
    * @brief The supported signature algorithms.
    */
    enum class SignatureAlgorithm {
        Undefined,
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA512
    };

    /**
    * @brief The handle to a key pair in the safe storage system.
    */
    class KeyPairHandle;

    /**
    * @brief Type used as input to the safe storage system.
    */
    using KeyPairHandlePtr = KeyPairHandle*;

    /**
    * @brief Creates a new key pair with the given name.
    * @param name The name of the key pair.
    * @param algorithm The signature algorithm to use.
    * @return Key pair handle if the key pair was created successfully, an empty optional otherwise.
    */
    std::unique_ptr<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm);

    /**
    * @brief Opens the key pair with the given name.
    * @param name The name of the key pair to open.
    * @return Key pair handle if the key pair was opened successfully, an empty optional otherwise.
    */
    std::unique_ptr<KeyPairHandle> open_key(std::string_view name);

    /**
    * @brief Deletes the key pair with the given name.
    * @param handle The handle to the key pair.
    * @return True if the key pair was deleted successfully, false otherwise.
    * @note After this function returns successfully, the key pair handle is no longer valid, and does not need to be released.
    */
    bool delete_key(const KeyPairHandlePtr handle);

    /**
    * @brief Signs the given data with the key pair with the given name.
    * @param handle The handle to the key pair.
    * @param data The hash to sign.
    * @return The signature if the data was signed successfully, an empty optional otherwise.
    * @note The data needs to be hashed before signing. The hash algorithm should match the given signature algorithm.
    */
    std::optional<std::string> sign(const KeyPairHandlePtr handle, std::string_view hash);

    /**
    * @brief Verifies the given data with the key pair with the given name.
    * @param handle The handle to the key pair.
    * @param hash The hash to verify.
    * @param signature The signature to verify.
    * @return True if the data was verified successfully, false otherwise.
    */
    bool verify(const KeyPairHandlePtr handle, std::string_view hash, std::string_view signature);

    /**
    * @brief Retrieves a verification (public) key with the given name.
    * @param handle The handle to the key pair.
    * @param vk_out The verification key.
    * @return True if the verification key retrieved successfully, false otherwise.
    */
    bool get_key(const KeyPairHandlePtr handle, std::string& vk_out);

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
    void release_key(const KeyPairHandlePtr handle);

    /**
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred.
    */
    std::string get_error();


    /**
    * @brief The handle to a key pair in the safe storage system.
    */
    class KeyPairHandle {
    public:
        /**
        * Constructor
        */
        KeyPairHandle() = delete;

        /**
        * Destructor
        */
        virtual ~KeyPairHandle() = default;

        /**
        * Get the name of the key pair.
        */
        std::string_view name() const { return name_; }

        /**
        * Get the algorithm of the key pair.
        */
        SignatureAlgorithm algorithm() const { return algorithm_; }

        /**
        * Get the size of the hash that should be used with this key pair.
        */
        std::size_t hash_size() const { return hash_size_; }

    protected:
        std::string name_;
        SignatureAlgorithm algorithm_;
        std::size_t hash_size_;

        KeyPairHandle(std::string_view name, SignatureAlgorithm algorithm);
    };
}
