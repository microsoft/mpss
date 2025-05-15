// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/key_info.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <optional>
#include <vector>
#include <memory>
#include <map>
#include <utility>
#include <array>

#include <gsl/span>

namespace mpss {
    /**
    * @brief Retrieves the last error that occurred.
    * @return The last error that occurred in the library.
    */
    [[nodiscard]] std::string get_error() noexcept;

    /**
    * @brief Determines whether the given signature algorithm is supported in the safe storage system.
    * @param algorithm The signature algorithm to verify
    * @return True if the signature algorithm is supported in safe storage, false otherwise.
    */
    [[nodiscard]] bool is_algorithm_supported(Algorithm algorithm);

    /**
    * @brief Verifies the given signature against the given hash data and public key.
    * @param[in] hash The hash to verify.
    * @param[in] public_key The public key used for verification.
    * @param[in] algorithm The signature algorithm used to create the signature.
    * @param[in] sig The signature to verify.
    * @return True if the data was verified successfully, false otherwise.
    */
    [[nodiscard]] bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> public_key, Algorithm algorithm, gsl::span<const std::byte> sig);


    /**
    * @brief Represents a handle to a key pair in the safe storage system.
    */
    class KeyPair {
    public:
        KeyPair() = delete;

        virtual ~KeyPair() = default;

        KeyPair(const KeyPair&) = delete;
        KeyPair& operator=(const KeyPair&) = delete;
        KeyPair(KeyPair&&) = delete;
        KeyPair& operator=(KeyPair&&) = delete;

        /**
        * @brief Get the key pair @ref Algorithm.
        */
        [[nodiscard]] Algorithm algorithm() const noexcept { return algorithm_; }

        /**
        * @brief Get the key pair @ref AlgorithmInfo.
        */
        [[nodiscard]] AlgorithmInfo algorithm_info() const noexcept { return info_; }

        /**
        * @brief Get @ref KeyInfo for the key pair
        */
        [[nodiscard]] KeyInfo key_info() const noexcept { return key_info_; }

        /**
        * @brief Creates a new key pair with the given name and algorithm.
        * @param[in] name The name of the key pair.
        * @param[in] algorithm The signature algorithm to use.
        * @return Key pair if the key pair was created successfully, a null pointer otherwise.
        * @note The name must be unique. If a key pair with the same name already exists, the function will fail.
        */
        [[nodiscard]] static std::unique_ptr<KeyPair> Create(std::string_view name, Algorithm algorithm);

        /**
        * @brief Opens the key pair with the given name.
        * @param[in] name The name of the key pair to open.
        * @return Key pair instance if the key pair was opened successfully, a null pointer otherwise.
        */
        [[nodiscard]] static std::unique_ptr<KeyPair> Open(std::string_view name);

        /**
        * @brief Deletes the key pair with the given name from the safe storage.
        * @return True if the key pair was deleted successfully, false otherwise.
        * @note After this function returns successfully, the key pair is no longer valid.
        */
        virtual bool delete_key() = 0;

        /**
        * @brief Signs the given hash with the key pair with the given name.
        * @param[in] hash The hash to sign.
        * @param[in,out] sig A buffer where the signature is written.
        * @return If sig is empty, returns the number of bytes required in sig to hold the signature.
        *         Otherwise, returns the number of bytes written to sig. Returns 0 if the operation failed.
        */
        virtual std::size_t sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const = 0;

        /**
        * @brief A convenience method to return the maximum signature buffer size.
        * @return Returns the maximum number of bytes required to hold the signature when calling @ref sign_hash.
        */
        [[nodiscard]] std::size_t sign_hash_size() const;

        /**
        * @brief Verifies the given signature against the given hash data with the key pair with the given name.
        * @param[in] hash The hash to verify.
        * @param[in] sig The signature to verify.
        * @return True if the data was verified successfully, false otherwise.
        */
        [[nodiscard]] virtual bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const = 0;

        /**
        * @brief Retrieves the public (verification) key.
        * @param[in,out] public_key An output parameter for the extracted public key.
        * @return If public_key is empty, returns the number of bytes required in public_key to hold the key.
        *         Otherwise, returns the number of bytes written to public_key. Returns 0 if the operation failed.
        * @note If the operation fails, public_key is not modified. There is no way to retrieve the secret (signing) key.
        */
        virtual std::size_t extract_key(gsl::span<std::byte> public_key) const = 0;

        /**
        * @brief A convenience method to return the required public (verification) key buffer size.
        * @return Returns the number of bytes required to hold the public key when calling @ref extract_key.
        */
        [[nodiscard]] std::size_t extract_key_size() const;

        /**
        * @brief Releases the key pair handle.
        * @note This function provides control to the user as to when to release the key pair handle.
        *       It is not necessary to call this function directly, they key pair handle will be released automatically
        *       when the @ref KeyPair instance is destroyed.
        *       After calling this function, the key pair handle is no longer valid.
        */
        virtual void release_key() = 0;

    protected:
        Algorithm algorithm_;
        AlgorithmInfo info_;
        KeyInfo key_info_;

        KeyPair(Algorithm algorithm, bool hardware_backed, const char* storage_description);
    };
}
