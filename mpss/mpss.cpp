// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "mpss/impl/backend_registry.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <array>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <utility>

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

std::optional<KeyLocation> location_with_defaults(std::string_view name,
                                                  std::optional<std::string_view> backend_name = std::nullopt)
{
    clear_error();

    // Refuse reentry before resolving defaults, which can initialize the backend registry.
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return std::nullopt;
    }

    // A supplied empty backend is invalid, not a request for the default backend.
    const std::string_view backend = backend_name ? *backend_name : impl::get_default_backend_name();
    if (!backend_name && backend.empty())
    {
        utils::log_and_set_error("No default backend available.");
        return std::nullopt;
    }

    // Only name-based calls pass through this helper; explicit locations never read a device default.
    KeyLocation location{.backend_name = std::string{backend}, .name = std::string{name}, .device_id = std::nullopt};
    if (!impl::default_device_id(location.backend_name, location.device_id))
    {
        return std::nullopt;
    }

    return location;
}
} // namespace

KeyLocation KeyPair::location() const
{
    return {.backend_name = backend_name_, .name = key_name_, .device_id = device_id_};
}

std::optional<KeyReference> KeyPair::reference() const
{
    // Location and algorithm are immutable; extract_key supplies the handle lock and identity checks.
    KeyReference result{location(), algorithm(), std::vector<std::byte>(extract_key_size())};
    const auto written = extract_key(result.public_key);
    if (0 == written || result.public_key.size() != written)
    {
        if (!has_error())
        {
            utils::log_and_set_error("Failed to capture the key-reference public key.");
        }
        return std::nullopt;
    }

    return result;
}

std::unique_ptr<KeyPair> KeyPair::Create(const KeyLocation &location, Algorithm algorithm, KeyPolicy policy)
{
    clear_error();
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return nullptr;
    }

    // Keep the name's existence check and creation serialized against other lifecycle operations.
    const std::scoped_lock lifecycle{utils::name_mutex(location.name)};
    return clear_error_on_success(impl::create_key(location, algorithm, policy));
}

std::unique_ptr<KeyPair> KeyPair::Open(const KeyLocation &location)
{
    clear_error();
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return nullptr;
    }

    const std::scoped_lock lifecycle{utils::name_mutex(location.name)};
    return clear_error_on_success(impl::open_key(location));
}

std::unique_ptr<KeyPair> KeyPair::Open(const KeyReference &reference)
{
    clear_error();
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return nullptr;
    }

    const std::size_t key_size = utils::get_public_key_size(reference.algorithm);
    if (0 == key_size || reference.public_key.size() != key_size)
    {
        utils::log_and_set_error("The key reference has an unsupported algorithm or invalid public key size.");
        return nullptr;
    }

    // Own the expected bytes before opening; a backend may also use them to disambiguate a route.
    std::vector<std::byte> expected = reference.public_key;
    const std::scoped_lock lifecycle{utils::name_mutex(reference.location.name)};
    auto key = impl::open_key(reference.location, expected);
    if (nullptr == key)
    {
        return nullptr;
    }

    // A location alone is not an identity: verify both the algorithm and public key before returning it.
    if (key->algorithm() != reference.algorithm)
    {
        utils::log_and_set_error("The opened key does not match the referenced algorithm.");
        return nullptr;
    }

    std::vector<std::byte> actual(key_size);
    const std::size_t written = key->extract_key(actual);
    if (0 == written)
    {
        return nullptr;
    }

    if (key_size != written)
    {
        utils::log_and_set_error("The opened key reported an invalid public key size.");
        return nullptr;
    }

    if (actual != expected)
    {
        utils::log_and_set_error("The opened key does not match the referenced public key.");
        return nullptr;
    }

    // Keep the verified identity on the handle for later extraction and signing checks.
    key->expected_public_key_ = std::move(expected);
    return clear_error_on_success(std::move(key));
}

bool KeyPair::Delete(const KeyLocation &location)
{
    clear_error();
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return false;
    }

    const std::scoped_lock lifecycle{utils::name_mutex(location.name)};
    return clear_error_on_success(impl::delete_key(location));
}

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
    const std::optional<KeyLocation> location = location_with_defaults(name);
    return location ? Create(*location, algorithm, policy) : nullptr;
}

std::unique_ptr<KeyPair> KeyPair::Create(std::string_view name, Algorithm algorithm, std::string_view backend_name,
                                         KeyPolicy policy)
{
    const std::optional<KeyLocation> location = location_with_defaults(name, backend_name);
    return location ? Create(*location, algorithm, policy) : nullptr;
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name)
{
    const std::optional<KeyLocation> location = location_with_defaults(name);
    return location ? Open(*location) : nullptr;
}

std::unique_ptr<KeyPair> KeyPair::Open(std::string_view name, std::string_view backend_name)
{
    const std::optional<KeyLocation> location = location_with_defaults(name, backend_name);
    return location ? Open(*location) : nullptr;
}

bool KeyPair::Delete(std::string_view name)
{
    const std::optional<KeyLocation> location = location_with_defaults(name);
    return location && Delete(*location);
}

bool KeyPair::Delete(std::string_view name, std::string_view backend_name)
{
    const std::optional<KeyLocation> location = location_with_defaults(name, backend_name);
    return location && Delete(*location);
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
        const std::scoped_lock lock{cache_mutex};
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
        const std::scoped_lock lock{cache_mutex};
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

std::optional<std::vector<std::string>> get_available_devices(std::string_view backend_name)
{
    clear_error();
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return std::nullopt;
    }
    return clear_error_on_success(impl::get_available_devices(backend_name));
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
    // known. What that one attempt reported is remembered, so a later caller is told what actually
    // happened rather than that a release it never made succeeded.
    if (released_)
    {
        return release_result_;
    }
    released_ = true;
    release_result_ = do_release_key();

    return release_result_;
}

bool KeyPair::release_key()
{
    // Refused rather than reported as released, since nothing was given up.
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return false;
    }
    const std::unique_lock lock{mtx_};
    return release_locked();
}

void KeyPair::release_from_destructor() noexcept
{
    // Destruction is not an operation, so it is not refused inside an interaction handler: the
    // release must still happen, or what the handle holds is leaked.
    try
    {
        const std::unique_lock lock{mtx_};
        static_cast<void>(release_locked());
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
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return false;
    }
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
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return 0;
    }
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

    if (expected_public_key_.empty())
    {
        return clear_error_on_success(do_sign_hash(hash, sig));
    }

    // Do not expose the backend's signature until the host verifies it against the expected key.
    std::vector<std::byte> signature(utils::get_max_signature_size(algorithm()));
    const std::size_t written = do_sign_hash(hash, signature);
    if (0 == written)
    {
        return 0;
    }

    if (written > signature.size())
    {
        utils::log_and_set_error("The backend returned an invalid signature size.");
        return 0;
    }

    const auto result = std::span<const std::byte>{signature}.first(written);
    clear_error();
    if (!impl::verify(backend_name_, hash, expected_public_key_, algorithm(), result))
    {
        if (!has_error())
        {
            utils::log_and_set_error("The signature does not verify against the referenced public key.");
        }
        return 0;
    }

    std::copy_n(signature.begin(), written, sig.begin());
    return clear_error_on_success(written);
}

bool KeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return false;
    }
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

    if (expected_public_key_.empty())
    {
        return clear_error_on_success(do_verify(hash, sig));
    }

    // The referenced key is the identity, so verify against it rather than against whatever the backend holds.
    return clear_error_on_success(impl::verify(backend_name_, hash, expected_public_key_, algorithm(), sig));
}

std::size_t KeyPair::extract_key(std::span<std::byte> public_key) const
{
    if (utils::in_interaction_handler())
    {
        utils::log_and_set_error("MPSS cannot be called from an interaction handler.");
        return 0;
    }
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

    if (expected_public_key_.empty())
    {
        return clear_error_on_success(do_extract_key(public_key));
    }

    // A changed key must not overwrite the caller's buffer or replace the handle's expected identity.
    std::vector<std::byte> actual(expected_public_key_.size());
    const std::size_t written = do_extract_key(actual);
    if (0 == written)
    {
        return 0;
    }

    if (written != expected_public_key_.size() || actual != expected_public_key_)
    {
        utils::log_and_set_error("The public key does not match the referenced public key.");
        return 0;
    }

    std::copy(actual.begin(), actual.end(), public_key.begin());
    return clear_error_on_success(written);
}

KeyPair::KeyPair(Algorithm algorithm, StorageTier storage_tier)
    : algorithm_{algorithm}, info_{get_algorithm_info(algorithm)}, key_info_{storage_tier}
{
    if (0 == info_.key_bits)
    {
        utils::log_and_set_error("Unsupported algorithm '{}'.", info_.type_str);
    }
}

} // namespace mpss
