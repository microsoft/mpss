// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/impl/backend_registry.h"
#include "mpss/utils/utilities.h"
#include <array>
#include <mutex>
#include <optional>
#include <shared_mutex>

namespace mpss
{

namespace
{
// Success is the truthy result: a non-null key, true, or a non-zero size. Explicit conversions are
// permitted, so that std::unique_ptr qualifies.
template <typename T>
concept boolean_testable = requires(const T &value) { static_cast<bool>(value); };

// A successful operation never reports an error. A backend may set one on an internal step - an
// existence probe, a provider fallback - and still succeed, so success is normalized here rather
// than in each backend.
template <boolean_testable T>
[[nodiscard]]
T clear_error_on_success(T result)
{
    if (static_cast<bool>(result))
    {
        clear_error();
    }
    return result;
}
} // namespace

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
    clear_error();
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}'.", name,
                     get_algorithm_info(algorithm).type_str);
    return clear_error_on_success(impl::create_key(name, algorithm, policy));
}

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, std::string_view backend_name,
                                         KeyPolicy policy)
{
    clear_error();
    utils::log_trace("KeyPair::Create called for key '{}' with algorithm '{}' on backend '{}'.", name,
                     get_algorithm_info(algorithm).type_str, backend_name);
    return clear_error_on_success(impl::create_key(backend_name, name, algorithm, policy));
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name)
{
    clear_error();
    utils::log_trace("KeyPair::Open called for key '{}'.", name);
    return clear_error_on_success(impl::open_key(name));
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, std::string_view backend_name)
{
    clear_error();
    utils::log_trace("KeyPair::Open called for key '{}' on backend '{}'.", name, backend_name);
    return clear_error_on_success(impl::open_key(backend_name, name));
}

bool KeyPair::Delete(std::string_view name)
{
    clear_error();
    utils::log_trace("KeyPair::Delete called for key '{}'.", name);
    const bool deleted = impl::delete_key(name);
    if (deleted)
    {
        clear_error();
    }
    return deleted;
}

bool KeyPair::Delete(std::string_view name, std::string_view backend_name)
{
    clear_error();
    utils::log_trace("KeyPair::Delete called for key '{}' on backend '{}'.", name, backend_name);
    const bool deleted = impl::delete_key(backend_name, name);
    if (deleted)
    {
        clear_error();
    }
    return deleted;
}

bool is_algorithm_available(Algorithm algorithm)
{
    clear_error();
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        utils::log_and_set_error("Unknown or unsupported algorithm.");
        return false;
    }

    // Cache results per algorithm to avoid repeated expensive probes.
    static std::mutex cache_mutex;
    static std::array<std::optional<bool>, algorithm_info.size()> cache{};

    const int idx = static_cast<int>(algorithm);
    {
        std::scoped_lock lock{cache_mutex};
        if (cache[idx])
        {
            // NOLINTBEGIN(bugprone-unchecked-optional-access) - guarded by the if above.
            utils::log_trace("Algorithm availability for '{}' returned from cache: {}.", info.type_str,
                             *cache[idx] ? "available" : "unavailable");
            return *cache[idx];
            // NOLINTEND(bugprone-unchecked-optional-access)
        }
    }

    // Delegate to the default backend.
    utils::log_trace("Probing algorithm availability for '{}'.", info.type_str);
    const bool available = impl::is_algorithm_available(algorithm);

    // Cache positive results only. A positive is stable -- the platform genuinely supports the algorithm.
    // A negative is the only direction that can be wrong and stick: a one-time probe can fail while the
    // keystore is temporarily unavailable (e.g. a locked device on a long-lived process) or a probe name
    // briefly collides, which memoizing would turn into a permanent, process-wide understatement of
    // availability. Re-probing a genuinely unsupported algorithm is cheap (create_key bails before
    // persisting a key), so negatives are simply not cached.
    if (available)
    {
        std::scoped_lock lock{cache_mutex};
        cache[idx] = true;
    }
    utils::log_trace("Algorithm '{}' is {}.", info.type_str, available ? "available" : "unavailable");
    return available;
}

bool is_algorithm_available(Algorithm algorithm, std::string_view backend_name)
{
    clear_error();
    const AlgorithmInfo info = get_algorithm_info(algorithm);
    if (0 == info.key_bits)
    {
        utils::log_and_set_error("Unknown or unsupported algorithm.");
        return false;
    }
    utils::log_trace("Checking algorithm availability for '{}' on backend '{}'.", info.type_str, backend_name);
    return impl::is_algorithm_available(backend_name, algorithm);
}

std::vector<Algorithm> get_available_algorithms()
{
    clear_error();
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
    clear_error();
    utils::log_trace("Standalone verify called with algorithm '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, hash.size(), sig.size());
    return clear_error_on_success(impl::verify(hash, public_key, algorithm, sig));
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig, std::string_view backend_name)
{
    clear_error();
    utils::log_trace("Standalone verify called with algorithm '{}' on backend '{}', hash size {}, signature size {}.",
                     get_algorithm_info(algorithm).type_str, backend_name, hash.size(), sig.size());
    return clear_error_on_success(impl::verify(backend_name, hash, public_key, algorithm, sig));
}

std::vector<const char *> get_available_backends()
{
    return impl::get_available_backends();
}

const char *get_default_backend_name()
{
    return impl::get_default_backend_name();
}

std::string get_error()
{
    return utils::get_error();
}

bool has_error() noexcept
{
    return utils::has_error();
}

void clear_error() noexcept
{
    utils::clear_error();
}

std::size_t KeyPair::sign_hash_size() const
{
    return utils::get_max_signature_size(algorithm());
}

std::size_t KeyPair::extract_key_size() const
{
    return utils::get_public_key_size(algorithm());
}

bool KeyPair::release_locked()
{
    // A handle is released explicitly by the caller and again when it is destroyed. Doing the work
    // once keeps a backend that reference counts a shared cache entry from giving up a hold that
    // belongs to another handle. Latching before the attempt rather than after a successful one
    // keeps that true of a release that fails part way through, where how much was given up is not
    // known.
    if (released_)
    {
        return true;
    }
    released_ = true;

    return do_release_key();
}

bool KeyPair::release_key()
{
    const std::unique_lock lock{mtx_};
    return release_locked();
}

void KeyPair::release_from_destructor() noexcept
{
    try
    {
        static_cast<void>(release_key());
    }
    // NOLINTNEXTLINE(bugprone-empty-catch) - a destructor must not propagate exceptions.
    catch (...)
    {
    }
}

KeyPair::~KeyPair()
{
    // Nothing can be released here: the backend has already been destroyed, so do_release_key no
    // longer resolves to it. All this can do is say that a backend destructor did not release, and
    // whatever that backend holds has been leaked.
    if (released_)
    {
        return;
    }

    try
    {
        utils::log_warning("Key pair handle destroyed without a release. The '{}' backend's destructor must call "
                           "release_from_destructor().",
                           backend_name_);
    }
    // Formatting the message allocates, and a destructor must not propagate exceptions.
    // NOLINTNEXTLINE(bugprone-empty-catch)
    catch (...)
    {
    }
}

bool KeyPair::delete_key()
{
    const std::unique_lock lock{mtx_};
    clear_error();
    if (released_)
    {
        utils::log_and_set_error("The key pair handle has been released.");
        return false;
    }
    if (!do_delete_key())
    {
        return false;
    }

    // The key is gone, so the name this handle carries no longer identifies anything it opened.
    // Releasing gives up whatever it held and latches it, so a key created later under the same
    // name cannot be reached through it. Whatever the release reports is not the caller's
    // business: the deletion they asked for succeeded, and a release that could not tidy up has
    // already said so in the log.
    static_cast<void>(release_locked());
    clear_error();
    return true;
}

std::size_t KeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    const std::shared_lock lock{mtx_};
    clear_error();
    if (released_)
    {
        utils::log_and_set_error("The key pair handle has been released.");
        return 0;
    }
    if (sig.empty())
    {
        // An empty signature buffer is a request for the required signature size.
        return utils::get_max_signature_size(algorithm());
    }
    if (!utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }
    return clear_error_on_success(do_sign_hash(hash, sig));
}

bool KeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    const std::shared_lock lock{mtx_};
    clear_error();
    if (released_)
    {
        utils::log_and_set_error("The key pair handle has been released.");
        return false;
    }
    if (hash.empty() || sig.empty())
    {
        utils::log_and_set_error("Nothing to verify.");
        return false;
    }
    if (!utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }
    return clear_error_on_success(do_verify(hash, sig));
}

std::size_t KeyPair::extract_key(std::span<std::byte> public_key) const
{
    const std::shared_lock lock{mtx_};
    clear_error();
    if (released_)
    {
        utils::log_and_set_error("The key pair handle has been released.");
        return 0;
    }
    if (public_key.empty())
    {
        // An empty output buffer is a request for the required public key size.
        return utils::get_public_key_size(algorithm());
    }
    if (!utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }
    return clear_error_on_success(do_extract_key(public_key));
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
