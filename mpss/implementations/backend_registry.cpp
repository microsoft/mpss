// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/backend_registry.h"
#include "mpss/config.h"
#include "mpss/implementations/os_backend.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <random>
#include <unordered_map>

namespace
{

std::string random_string(std::size_t length)
{
    // Note: This function is not cryptographically secure. It is only used for generating random key names for
    // probing algorithm support, so this is sufficient for our purposes.
    static constexpr char chars[] = "0123456789"
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz";
    static constexpr std::size_t char_count = sizeof(chars) - 1;

    thread_local std::mt19937 rng{std::random_device{}()};
    thread_local std::uniform_int_distribution<std::size_t> dist(0, char_count - 1);

    std::string result(length, '\0');
    std::ranges::generate(result, [&] { return chars[dist(rng)]; });
    return result;
}

} // namespace

namespace mpss::impl
{

class BackendNameSetter
{
  public:
    static void set(KeyPair &kp, std::string name)
    {
        kp.backend_name_ = std::move(name);
    }
};

// Maximum key name length. The YubiKey backend stores the name in an X.509 certificate's CN field
// and reads it back into a fixed-size buffer, so names beyond this limit would be silently truncated.
constexpr std::size_t max_key_name_length = 255;

#ifdef MPSS_BACKEND_YUBIKEY
// Forward declaration for YubiKey backend registration.
void register_yubikey_backend();
#endif

/**
 * @brief Registry for managing multiple backend implementations.
 *
 * The registry allows registration of multiple backends and selection
 * of the active backend based on environment variables or system defaults.
 * This class is an implementation detail and is not exposed in the public API.
 */
class BackendRegistry
{
  public:
    /**
     * @brief Get the singleton instance of the registry.
     */
    static BackendRegistry &instance()
    {
        static BackendRegistry registry;
        return registry;
    }

    /**
     * @brief Register a backend.
     * @param[in] backend The backend to register.
     */
    void register_backend(std::shared_ptr<Backend> backend)
    {
        if (nullptr == backend)
        {
            utils::log_warn("Attempted to register null backend.");
            return;
        }

        const std::string backend_name = backend->name();
        if (backends_.contains(backend_name))
        {
            utils::log_warn("Backend '{}' already registered, ignoring.", backend_name);
            return;
        }
        backends_[backend_name] = backend;
        utils::log_info("Registered backend: {}", backend_name);
    }

    /**
     * @brief Get the currently active backend.
     * @return Pointer to the active backend, or nullptr if none is selected.
     */
    [[nodiscard]] std::shared_ptr<Backend> get_active_backend()
    {
        initialize_if_needed();

        if (nullptr == active_backend_)
        {
            utils::log_and_set_error("No active backend available.");
        }

        return active_backend_;
    }

    /**
     * @brief Get a backend by name.
     * @param[in] name The backend name.
     * @return Pointer to the backend, or nullptr if not found.
     */
    [[nodiscard]] std::shared_ptr<Backend> get_backend(std::string_view name)
    {
        initialize_if_needed();

        const std::string backend_name{name};
        const auto it = backends_.find(backend_name);
        if (backends_.end() != it)
        {
            return it->second;
        }

        return nullptr;
    }

    /**
     * @brief Get the names of all available (registered and usable) backends.
     * @return Vector of backend names.
     */
    [[nodiscard]] std::vector<std::string> get_available_backend_names()
    {
        initialize_if_needed();

        std::vector<std::string> names;
        for (const auto &[name, backend] : backends_)
        {
            if (backend->is_available())
            {
                names.push_back(name);
            }
        }
        return names;
    }

    /**
     * @brief Ensure backends are registered and the active backend is selected.
     */
    void initialize_if_needed()
    {
        if (initialized_)
        {
            return;
        }
        initialized_ = true;

        // Register available backends.
#if defined(_WIN32) || defined(__APPLE__) || defined(__ANDROID__)
        register_os_backend();
#endif
#ifdef MPSS_BACKEND_YUBIKEY
        register_yubikey_backend();
#endif

        // Check MPSS_DEFAULT_BACKEND environment variable.
        const char *env_backend = std::getenv("MPSS_DEFAULT_BACKEND");
        if (nullptr != env_backend && std::strlen(env_backend) > 0)
        {
            const std::string requested{env_backend};
            const std::string backend_name{requested};
            const auto it = backends_.find(backend_name);
            if (backends_.end() != it && it->second->is_available())
            {
                active_backend_ = it->second;
                utils::log_info("Using backend from MPSS_DEFAULT_BACKEND: {}", requested);
                return;
            }
            utils::log_and_set_error("Requested backend '{}' not available or not found.", requested);
            return;
        }

        // Fall back to platform default.
        const std::string default_name = platform_default_backend_name();
        if (!default_name.empty())
        {
            const auto it = backends_.find(default_name);
            if (backends_.end() != it && it->second->is_available())
            {
                active_backend_ = it->second;
                utils::log_info("Using default backend: {}", default_name);
                return;
            }
        }

        utils::log_and_set_error("No available backend found.");
    }

  private:
    BackendRegistry() = default;

    std::unordered_map<std::string, std::shared_ptr<Backend>> backends_;
    std::shared_ptr<Backend> active_backend_;
    bool initialized_ = false;

    /**
     * @brief Get the platform-specific default backend name.
     */
    [[nodiscard]] std::string platform_default_backend_name() const
    {
#if defined(_WIN32)
        return "os";
#elif defined(__APPLE__)
        return "os";
#elif defined(__ANDROID__)
        return "os";
#elif defined(__linux__)
        // Linux: prefer YubiKey as it's the only available backend.
        if (backends_.count("yubikey") && backends_.at("yubikey")->is_available())
        {
            return "yubikey";
        }
        return "";
#else
        return "";
#endif
    }
};

// Free function to register a backend with the internal registry.
void register_backend(std::shared_ptr<Backend> backend)
{
    BackendRegistry::instance().register_backend(std::move(backend));
}

// Default-backend free functions.
bool is_algorithm_available(Algorithm algorithm)
{
    const auto backend = BackendRegistry::instance().get_active_backend();
    if (nullptr == backend)
    {
        return false;
    }
    return backend->is_algorithm_available(algorithm);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
{
    if (name.empty())
    {
        utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }
    if (name.size() > max_key_name_length)
    {
        utils::log_warn("Key name exceeds maximum length of {} characters.", max_key_name_length);
        return nullptr;
    }

    const auto backend = BackendRegistry::instance().get_active_backend();
    if (nullptr == backend)
    {
        utils::log_and_set_error("No active backend available for creating key '{}'.", name);
        return nullptr;
    }

    utils::log_debug("Creating key '{}' with algorithm '{}' using backend '{}'.", name,
                     get_algorithm_info(algorithm).type_str, backend->name());
    auto key = backend->create_key(name, algorithm);
    if (nullptr != key)
    {
        utils::log_debug("Key '{}' created successfully on backend '{}'.", name, backend->name());
        BackendNameSetter::set(*key, backend->name());
    }
    return key;
}

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }
    if (name.size() > max_key_name_length)
    {
        utils::log_warn("Key name exceeds maximum length of {} characters.", max_key_name_length);
        return nullptr;
    }

    const auto backend = BackendRegistry::instance().get_active_backend();
    if (nullptr == backend)
    {
        utils::log_and_set_error("No active backend available for opening key '{}'.", name);
        return nullptr;
    }

    utils::log_debug("Opening key '{}' using backend '{}'.", name, backend->name());
    auto key = backend->open_key(name);
    if (nullptr != key)
    {
        utils::log_debug("Key '{}' opened successfully on backend '{}'.", name, backend->name());
        BackendNameSetter::set(*key, backend->name());
    }
    return key;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    const auto backend = BackendRegistry::instance().get_active_backend();
    if (nullptr == backend)
    {
        utils::log_and_set_error("No active backend available for verification.");
        return false;
    }

    return backend->verify(hash, public_key, algorithm, sig);
}

// Explicit-backend-name overloads.
std::unique_ptr<KeyPair> create_key(std::string_view backend_name, std::string_view name, Algorithm algorithm)
{
    if (name.empty())
    {
        utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }
    if (name.size() > max_key_name_length)
    {
        utils::log_warn("Key name exceeds maximum length of {} characters.", max_key_name_length);
        return nullptr;
    }

    auto &registry = BackendRegistry::instance();
    const auto backend = registry.get_backend(backend_name);
    if (nullptr == backend || !backend->is_available())
    {
        utils::log_and_set_error("Backend '{}' not available.", backend_name);
        return nullptr;
    }

    auto key = backend->create_key(name, algorithm);
    if (nullptr != key)
    {
        BackendNameSetter::set(*key, backend->name());
    }
    return key;
}

std::unique_ptr<KeyPair> open_key(std::string_view backend_name, std::string_view name)
{
    if (name.empty())
    {
        utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }
    if (name.size() > max_key_name_length)
    {
        utils::log_warn("Key name exceeds maximum length of {} characters.", max_key_name_length);
        return nullptr;
    }

    auto &registry = BackendRegistry::instance();
    const auto backend = registry.get_backend(backend_name);
    if (nullptr == backend || !backend->is_available())
    {
        utils::log_and_set_error("Backend '{}' not available.", backend_name);
        return nullptr;
    }

    auto key = backend->open_key(name);
    if (nullptr != key)
    {
        BackendNameSetter::set(*key, backend->name());
    }
    return key;
}

bool verify(std::string_view backend_name, std::span<const std::byte> hash, std::span<const std::byte> public_key,
            Algorithm algorithm, std::span<const std::byte> sig)
{
    auto &registry = BackendRegistry::instance();
    const auto backend = registry.get_backend(backend_name);
    if (nullptr == backend || !backend->is_available())
    {
        utils::log_and_set_error("Backend '{}' not available.", backend_name);
        return false;
    }

    return backend->verify(hash, public_key, algorithm, sig);
}

// Discovery functions.
std::vector<std::string> get_available_backends()
{
    return BackendRegistry::instance().get_available_backend_names();
}

std::string get_default_backend_name()
{
    auto &registry = BackendRegistry::instance();
    const auto active = registry.get_active_backend();
    if (nullptr != active)
    {
        return active->name();
    }
    return "";
}

bool Backend::is_algorithm_available(Algorithm algorithm) const
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return false;
    }

    // Sample a random name for a key and try creating it.
    const std::string random_key = "MPSS_TEST_KEY_" + random_string(16) + "_CAN_DELETE";
    std::unique_ptr<KeyPair> key = create_key(random_key, algorithm);

    // Could we even create a key?
    if (nullptr == key)
    {
        return false;
    }
    SCOPE_GUARD({
        // Delete the key if it was created.
        const bool key_deleted = key->delete_key();
        if (!key_deleted)
        {
            utils::log_and_set_error("Created key could not be deleted: {}", random_key);
        }
    });

    // Create some data and sign.
    const std::vector<std::byte> hash(info.hash_bits / 8, static_cast<std::byte>('a'));
    const std::size_t sig_size = key->sign_hash(hash, {});
    if (0 == sig_size)
    {
        return false;
    }

    std::vector<std::byte> sig(sig_size);
    const std::size_t written = key->sign_hash(hash, sig);
    if (0 == written)
    {
        return false;
    }

    return true;
}

} // namespace mpss::impl
