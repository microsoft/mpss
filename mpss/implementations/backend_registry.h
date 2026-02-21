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
 * Each backend (OS-native, YubiKey, etc.) must implement this interface
 * and register itself with the BackendRegistry.
 */
class Backend
{
  public:
    virtual ~Backend() = default;

    /**
     * @brief Get the name of this backend.
     * @return Backend name (e.g., "os", "yubikey")
     */
    [[nodiscard]] virtual std::string name() const = 0;

    /**
     * @brief Create a new key pair.
     * @param[in] name The name of the key pair.
     * @param[in] algorithm The signature algorithm to use.
     * @return Key pair if successful, nullptr otherwise.
     */
    [[nodiscard]] virtual std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm) const = 0;

    /**
     * @brief Open an existing key pair.
     * @param[in] name The name of the key pair.
     * @return Key pair if successful, nullptr otherwise.
     */
    [[nodiscard]] virtual std::unique_ptr<KeyPair> open_key(std::string_view name) const = 0;

    /**
     * @brief Verify a signature (standalone, without a key pair object).
     * @param[in] hash The hash to verify.
     * @param[in] public_key The public key for verification.
     * @param[in] algorithm The signature algorithm.
     * @param[in] sig The signature to verify.
     * @return true if verification succeeds, false otherwise.
     */
    [[nodiscard]] virtual bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key,
                                      Algorithm algorithm, std::span<const std::byte> sig) const = 0;

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
    [[nodiscard]] virtual bool is_algorithm_available(Algorithm algorithm) const;

    /**
     * @brief Check if this backend is available on the current system.
     * @return true if the backend can be used, false otherwise.
     */
    [[nodiscard]] virtual bool is_available() const = 0;
};

// Helper functions that delegate to the active (default) backend.
[[nodiscard]] bool is_algorithm_available(Algorithm algorithm);

[[nodiscard]] std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm);

[[nodiscard]] std::unique_ptr<KeyPair> open_key(std::string_view name);

[[nodiscard]] bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                          std::span<const std::byte> sig);

// Overloads that take an explicit backend name.
[[nodiscard]] std::unique_ptr<KeyPair> create_key(std::string_view backend_name, std::string_view name,
                                                  Algorithm algorithm);

[[nodiscard]] std::unique_ptr<KeyPair> open_key(std::string_view backend_name, std::string_view name);

[[nodiscard]] bool verify(std::string_view backend_name, std::span<const std::byte> hash,
                          std::span<const std::byte> public_key, Algorithm algorithm, std::span<const std::byte> sig);

/// @brief Get the names of all available backends.
[[nodiscard]] std::vector<std::string> get_available_backends();

/// @brief Get the name of the default backend.
[[nodiscard]] std::string get_default_backend_name();

/// @brief Register a backend with the internal registry.
/// @param[in] backend The backend to register.
void register_backend(std::shared_ptr<Backend> backend);

} // namespace mpss::impl
