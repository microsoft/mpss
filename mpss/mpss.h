// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/defines.h"
#include "mpss/key_info.h"
#include "mpss/key_policy.h"
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mpss
{

// Forward declaration for backend registry access.
namespace impl
{
class BackendNameSetter;
} // namespace impl

/**
 * @brief Retrieves the last error that occurred.
 * @return The last error that occurred in the library.
 */
[[nodiscard]]
MPSS_DECOR std::string get_error();

/**
 * @brief Determines whether the given signature algorithm is available in the default backend.
 *
 * This performs a runtime probe (key creation, signing, verification, deletion) to check that
 * the algorithm works end-to-end. Results are cached after the first call per algorithm.
 *
 * @param algorithm The signature algorithm to check.
 * @return true if the algorithm is available, false otherwise.
 */
[[nodiscard]]
MPSS_DECOR bool is_algorithm_available(Algorithm algorithm);

/**
 * @brief Determines whether the given signature algorithm is available in a specific backend.
 * @param algorithm The signature algorithm to check.
 * @param backend_name The backend to check (e.g., "os", "yubikey").
 * @return true if the algorithm is available, false otherwise.
 */
[[nodiscard]]
MPSS_DECOR bool is_algorithm_available(Algorithm algorithm, std::string_view backend_name);

/**
 * @brief Returns all signature algorithms available in the default backend.
 * @return A vector of available @ref Algorithm values.
 */
[[nodiscard]]
MPSS_DECOR std::vector<Algorithm> get_available_algorithms();

/**
 * @brief Verifies the given signature against the given hash data and public key.
 * @param[in] hash The hash to verify.
 * @param[in] public_key The public key used for verification.
 * @param[in] algorithm The signature algorithm used to create the signature.
 * @param[in] sig The signature to verify.
 * @return true if the data was verified successfully, false otherwise.
 */
[[nodiscard]]
MPSS_DECOR bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                       std::span<const std::byte> sig);

/**
 * @brief Verifies a signature using a specific backend.
 * @param[in] hash The hash to verify.
 * @param[in] public_key The public key used for verification.
 * @param[in] algorithm The signature algorithm.
 * @param[in] sig The signature to verify.
 * @param[in] backend_name The backend to use (e.g., "os", "yubikey").
 * @return true if verified successfully, false otherwise.
 */
[[nodiscard]]
MPSS_DECOR bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                       std::span<const std::byte> sig, std::string_view backend_name);

/**
 * @brief Get the names of all available backends.
 * @return Vector of backend names (e.g., {"os", "yubikey"}).
 */
[[nodiscard]]
MPSS_DECOR std::vector<std::string> get_available_backends();

/**
 * @brief Get the name of the default backend.
 * @return The default backend name, or an empty string if none is available.
 */
[[nodiscard]]
MPSS_DECOR std::string get_default_backend_name();

/**
 * @brief Represents a handle to a key pair in the safe storage system.
 */
class MPSS_DECOR KeyPair
{
    friend class impl::BackendNameSetter;

  public:
    KeyPair() = delete;

    virtual ~KeyPair() = default;

    KeyPair(const KeyPair &) = delete;
    KeyPair &operator=(const KeyPair &) = delete;
    KeyPair(KeyPair &&) = delete;
    KeyPair &operator=(KeyPair &&) = delete;

    /**
     * @brief Get the key pair @ref Algorithm.
     */
    [[nodiscard]]
    Algorithm algorithm() const noexcept
    {
        return algorithm_;
    }

    /**
     * @brief Get the key pair @ref AlgorithmInfo.
     */
    [[nodiscard]]
    AlgorithmInfo algorithm_info() const noexcept
    {
        return info_;
    }

    /**
     * @brief Get @ref KeyInfo for the key pair.
     */
    [[nodiscard]]
    KeyInfo key_info() const noexcept
    {
        return key_info_;
    }

    /**
     * @brief Get the name of the backend that created or opened this key pair.
     */
    [[nodiscard]]
    std::string_view backend_name() const noexcept
    {
        return backend_name_;
    }

    /**
     * @brief Creates a new key pair with the given name and algorithm.
     * @param[in] name The name of the key pair. Must not exceed 64 characters.
     * @param[in] algorithm The signature algorithm to use.
     * @param[in] policy Backend-specific key policy. Defaults to KeyPolicy::none (use env vars / backend defaults).
     * @return Key pair if the key pair was created successfully, a null pointer otherwise.
     * @note The name must be unique. If a key pair with the same name already exists, the
     * function will return a null pointer.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Create(std::string_view name, Algorithm algorithm,
                                           KeyPolicy policy = KeyPolicy::none);

    /**
     * @brief Creates a new key pair using a specific backend.
     * @param[in] name The name of the key pair. Must not exceed 64 characters.
     * @param[in] algorithm The signature algorithm to use.
     * @param[in] backend_name The backend to use (e.g., "os", "yubikey").
     * @param[in] policy Backend-specific key policy. Defaults to KeyPolicy::none (use env vars / backend defaults).
     * @return Key pair if created successfully, nullptr otherwise.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Create(std::string_view name, Algorithm algorithm, std::string_view backend_name,
                                           KeyPolicy policy = KeyPolicy::none);

    /**
     * @brief Opens the key pair with the given name.
     * @param[in] name The name of the key pair to open. Must not exceed 64 characters.
     * @return Key pair instance if the key pair was opened successfully, a null pointer
     * otherwise.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Open(std::string_view name);

    /**
     * @brief Opens the key pair with the given name using a specific backend.
     * @param[in] name The name of the key pair to open. Must not exceed 64 characters.
     * @param[in] backend_name The backend to use (e.g., "os", "yubikey").
     * @return Key pair if opened successfully, nullptr otherwise.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Open(std::string_view name, std::string_view backend_name);

    /**
     * @brief Deletes the key pair with the given name from the safe storage.
     * @return true if the key pair was deleted successfully, false otherwise.
     * @note After this function returns successfully, the key pair is no longer valid.
     */
    virtual bool delete_key() = 0;

    /**
     * @brief Signs the given hash data with the key pair.
     * @param[in] hash The hash to sign.
     * @param[in,out] sig A buffer where the signature is written.
     * @return If sig is empty, returns the number of bytes required in sig to hold the
     * signature. Otherwise, returns the number of bytes written to sig. Returns 0 if the
     * operation failed.
     */
    [[nodiscard]]
    virtual std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const = 0;

    /**
     * @brief A convenience method to return the maximum signature buffer size.
     * @return Returns the maximum number of bytes required to hold the signature when calling
     * @ref sign_hash.
     */
    [[nodiscard]]
    std::size_t sign_hash_size() const;

    /**
     * @brief Verifies the given signature against the given hash data with the key pair with
     * the given name.
     * @param[in] hash The hash to verify.
     * @param[in] sig The signature to verify.
     * @return true if the signature was verified successfully, false otherwise.
     */
    [[nodiscard]]
    virtual bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const = 0;

    /**
     * @brief Retrieves the public (verification) key.
     * @param[in,out] public_key An output parameter for the extracted public key.
     * @return If public_key is empty, returns the number of bytes required in public_key to
     * hold the key. Otherwise, returns the number of bytes written to public_key. Returns 0 if
     * the operation failed.
     * @note If the operation fails, public_key is not modified. There is no way to retrieve the
     * secret (signing) key.
     */
    [[nodiscard]]
    virtual std::size_t extract_key(std::span<std::byte> public_key) const = 0;

    /**
     * @brief A convenience method to return the required public (verification) key buffer size.
     * @return Returns the number of bytes required to hold the public key when calling @ref
     * extract_key.
     */
    [[nodiscard]]
    std::size_t extract_key_size() const;

    /**
     * @brief Releases the key pair handle.
     *
     * This function provides control to the user as to when to release the key pair handle. It is not necessary to
     * call this function directly, they key pair handle will be released automatically when the @ref KeyPair
     * instance is destroyed. After calling this function, the key pair handle is no longer valid.
     */
    virtual void release_key() = 0;

  protected:
    // NOLINTBEGIN(*-non-private-member-variables-in-classes) - subclasses need direct access.
    Algorithm algorithm_;
    AlgorithmInfo info_;
    KeyInfo key_info_;
    std::string backend_name_;
    // NOLINTEND(*-non-private-member-variables-in-classes)

    KeyPair(Algorithm algorithm, bool hardware_backed, const char *storage_description);
};

} // namespace mpss
