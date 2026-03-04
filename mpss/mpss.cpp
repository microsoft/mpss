// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/impl/backend_registry.h"
#include "mpss/utils/utilities.h"
#include <array>
#include <mutex>
#include <optional>

namespace mpss
{

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}'.", name,
                     get_algorithm_info(algorithm).type_str);
    return impl::create_key(name, algorithm, policy);
}

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, std::string_view backend_name,
                                         KeyPolicy policy)
{
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}' on backend '{}'.", name,
                     get_algorithm_info(algorithm).type_str, backend_name);
    return impl::create_key(backend_name, name, algorithm, policy);
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name)
{
    utils::log_trace("KeyPair::Open called for key '{}'.", name);
    return impl::open_key(name);
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, std::string_view backend_name)
{
    utils::log_trace("KeyPair::Open called for key '{}' on backend '{}'.", name, backend_name);
    return impl::open_key(backend_name, name);
}

bool is_algorithm_available(Algorithm algorithm)
{
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        return false;
    }

    // Cache results per algorithm to avoid repeated expensive probes.
    static std::mutex cache_mutex;
    static std::array<std::optional<bool>, algorithm_info.size()> cache{};

    const int idx = static_cast<int>(algorithm);
    {
        std::lock_guard lock{cache_mutex};
        if (cache[idx])
        {
            utils::log_trace("Algorithm availability for '{}' returned from cache: {}.", info.type_str,
                             *cache[idx] ? "available" : "unavailable");
            return *cache[idx];
        }
    }

    // Delegate to the active backend.
    utils::log_trace("Probing algorithm availability for '{}'.", info.type_str);
    const bool available = impl::is_algorithm_available(algorithm);

    std::lock_guard lock{cache_mutex};
    cache[idx] = available;
    utils::log_trace("Algorithm '{}' is {}.", info.type_str, available ? "available" : "unavailable");
    return available;
}

std::vector<Algorithm> get_available_algorithms()
{
    std::vector<Algorithm> result;
    for (const auto &[alg, info] : algorithm_info)
    {
        if (Algorithm::unsupported == alg)
        {
            continue;
        }
        if (is_algorithm_available(alg))
        {
            result.push_back(alg);
        }
    }
    return result;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    utils::log_trace("Standalone verify called with algorithm '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, hash.size(), sig.size());
    return impl::verify(hash, public_key, algorithm, sig);
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig, std::string_view backend_name)
{
    utils::log_trace("Standalone verify called with algorithm '{}' on backend '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, backend_name, hash.size(), sig.size());
    return impl::verify(backend_name, hash, public_key, algorithm, sig);
}

std::vector<std::string> get_available_backends()
{
    return impl::get_available_backends();
}

std::string get_default_backend_name()
{
    return impl::get_default_backend_name();
}

std::string get_error()
{
    return utils::get_error();
}

std::size_t KeyPair::sign_hash_size() const
{
    return utils::get_max_signature_size(algorithm());
}

std::size_t KeyPair::extract_key_size() const
{
    return utils::get_public_key_size(algorithm());
}

KeyPair::KeyPair(Algorithm algorithm, bool hardware_backed, const char *storage_description)
    : algorithm_{algorithm}, info_{get_algorithm_info(algorithm)}, key_info_{hardware_backed, storage_description}
{
    if (0 == info_.key_bits)
    {
        utils::log_and_set_error("Unsupported algorithm '{}'.", info_.type_str);
    }
}

} // namespace mpss
