// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/mpss.h"
#include <vector>

namespace mpss::impl
{

/**
 * @brief Interface for a backend implementation.
 *
 * Each built-in backend (OS-native, YubiKey, etc.) implements this interface
 * and is installed by the BackendRegistry during initialization.
 */
class Backend
{
  public:
    virtual ~Backend() = default;

    /**
     * @brief Get the name of this backend.
     * @return Backend name (e.g., "os", "yubikey")
     */
    [[nodiscard]]
    virtual const char *name() const = 0;

    /**
     * @brief Create a new key pair.
     * @param[in] location The explicit backend, name and optional device identifier.
     * @param[in] algorithm The signature algorithm to use.
     * @param[in] policy Backend-specific key policy.
     * @return Key pair if successful, nullptr otherwise.
     */
    [[nodiscard]]
    virtual std::unique_ptr<KeyPair> create_key(const KeyLocation &location, Algorithm algorithm,
                                                KeyPolicy policy) const = 0;

    /**
     * @brief Open an existing key pair.
     * @param[in] location The explicit backend, name and optional device identifier.
     * @param[in] expected_public_key Optional expected key that a backend may use to select among
     * matching device routes. A backend may ignore it; the caller verifies the opened key against it.
     * @return Key pair if successful, nullptr otherwise.
     */
    [[nodiscard]]
    virtual std::unique_ptr<KeyPair> open_key(const KeyLocation &location,
                                              std::span<const std::byte> expected_public_key = {}) const = 0;

    /**
     * @brief Delete every key stored under a name, without opening it.
     *
     * Resolution refuses a name held by more than one key, so a name in that state cannot be
     * opened and therefore cannot be deleted through a key pair. This clears the name instead,
     * removing every key under it: leaving one behind would let a refused name start resolving
     * again, to whichever key survived.
     *
     * @param[in] location The name and selected storage to clear.
     * @return true if the name holds no key afterwards, including when it held none to begin
     * with; false if a key could not be removed or the storage could not be read.
     */
    [[nodiscard]]
    virtual bool delete_key(const KeyLocation &location) const = 0;

    [[nodiscard]]
    virtual std::optional<std::vector<std::string>> available_devices() const
    {
        return std::vector<std::string>{};
    }

    /**
     * @brief Resolves the device that this backend's environment default selects for name-based calls.
     *
     * Leaves device_id unset when there is no default, which requests automatic selection. Returns
     * false, with the error set, when a default is present but invalid, so that a misconfigured
     * default is refused rather than replaced by whichever device happens to be reachable.
     */
    [[nodiscard]]
    virtual bool default_device_id(std::optional<std::string> &device_id) const
    {
        device_id.reset();
        return true;
    }

    /**
     * @brief Verify a signature (standalone, without a key pair object).
     * @param[in] hash The hash to verify.
     * @param[in] public_key The public key for verification.
     * @param[in] algorithm The signature algorithm.
     * @param[in] sig The signature to verify.
     * @return true if verification succeeds, false otherwise.
     */
    [[nodiscard]]
    virtual bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                        std::span<const std::byte> sig) const = 0;

    /**
     * @brief Check if the given algorithm is supported by this backend.
     *
     * The default implementation probes support by creating, signing with,
     * and deleting a temporary key. Backends may override this with a
     * cheaper check (e.g., a static lookup table).
     *
     * @param algorithm The algorithm to check.
     * @return true if the algorithm is supported, false otherwise.
     */
    [[nodiscard]]
    virtual bool is_algorithm_available(Algorithm algorithm) const;
};

[[nodiscard]]
std::unique_ptr<KeyPair> create_key(const KeyLocation &location, Algorithm algorithm, KeyPolicy policy);

[[nodiscard]]
std::unique_ptr<KeyPair> open_key(const KeyLocation &location, std::span<const std::byte> expected_public_key = {});

[[nodiscard]]
bool delete_key(const KeyLocation &location);

[[nodiscard]]
std::optional<std::vector<std::string>> get_available_devices(std::string_view backend_name);

// Resolves the named backend's environment device default; see Backend::default_device_id. An
// unknown backend has no default, and is reported by the operation that goes on to use it.
[[nodiscard]]
bool default_device_id(std::string_view backend_name, std::optional<std::string> &device_id);

[[nodiscard]]
bool verify(std::string_view backend_name, std::span<const std::byte> hash, std::span<const std::byte> public_key,
            Algorithm algorithm, std::span<const std::byte> sig);

[[nodiscard]]
bool is_algorithm_available(std::string_view backend_name, Algorithm algorithm);

// Default-backend overloads that resolve the default backend and delegate to the above.
[[nodiscard]]
bool is_algorithm_available(Algorithm algorithm);

[[nodiscard]]
bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig);

/// @brief Get the names of all available backends.
[[nodiscard]]
std::vector<const char *> get_available_backends();

/// @brief Get the name of the default backend.
[[nodiscard]]
const char *get_default_backend_name();

} // namespace mpss::impl
