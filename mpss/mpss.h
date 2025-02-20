// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <vector>
#include <memory>

#include <gsl/gsl>

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
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred in the library.
    */
    std::string get_error();

    /**
    * @brief Determines whether the given signature algorithm is supported in the safe storage system.
    * @param algorithm The signature algorithm to verify
    * @return True if the signature algorithm is supported in safe storage, false otherwise.
    */
    bool is_safe_storage_supported(SignatureAlgorithm algorithm);


    /**
    * @brief Represents a key pair in the safe storage system.
    */
    class KeyPair {
    public:
        /**
        * Constructor
        */
        KeyPair() = delete;

        /**
        * Destructor
        */
        virtual ~KeyPair() = default;

        /**
        * Get the name of the key pair.
        */
        std::string_view name() const { return name_; }

        /**
        * Get the algorithm of the key pair.
        */
        SignatureAlgorithm algorithm() const { return algorithm_; }

        /**
        * @brief Creates a new key pair with the given name and algorithm.
        * @param name The name of the key pair.
        * @param algorithm The signature algorithm to use.
        * @return Key pair if the key pair was created successfully, a null pointer otherwise.
        */
        static std::unique_ptr<KeyPair> create(std::string_view name, SignatureAlgorithm algorithm);

        /**
        * @brief Opens the key pair with the given name.
        * @param name The name of the key pair to open.
        * @return Key pair instance if the key pair was opened successfully, a null pointer otherwise.
        */
        static std::unique_ptr<KeyPair> open(std::string_view name);

        /**
        * @brief Deletes the key pair with the given name from the safe storage.
        * @return True if the key pair was deleted successfully, false otherwise.
        * @note After this function returns successfully, the key pair is no longer valid.
        */
        bool delete_key();

        /**
        * @brief Signs the given data with the key pair with the given name.
        * @param data The hash to sign.
        * @return The signature if the data was signed successfully, an empty optional otherwise.
        * @note The data needs to be hashed before signing. The hash algorithm should match the given signature algorithm.
        */
        std::optional<std::vector<std::byte>> sign(gsl::span<std::byte> hash) const;

        /**
        * @brief Verifies the given data with the key pair with the given name.
        * @param hash The hash to verify.
        * @param signature The signature to verify.
        * @return True if the data was verified successfully, false otherwise.
        */
        bool verify(gsl::span<std::byte> hash, gsl::span<std::byte> signature) const;

        /**
        * @brief Retrieves a verification (public) key with the given name.
        * @param vk_out The verification key.
        * @return True if the verification key retrieved successfully, false otherwise.
        */
        bool get_verification_key(std::vector<std::byte>& vk_out) const;

        /**
        * @brief Releases the key pair handle.
        * @note This function provides control to the user as to when to release the key pair handle.
        *       It is not necessary to call this function directly, they key pair handle will be released automatically
        *       when the @ref KeyPair instance is destroyed.
        *       After calling this function, the key pair handle is no longer valid.
        */
        void release_key();

    protected:
        std::string name_;
        SignatureAlgorithm algorithm_;
        std::size_t hash_size_;

        KeyPair(std::string_view name, SignatureAlgorithm algorithm);
    };
}
