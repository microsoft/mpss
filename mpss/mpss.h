// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/defines.h"
#include "mpss/key_info.h"
#include "mpss/key_policy.h"
#include "mpss/key_reference.h"
#include <cstddef>
#include <memory>
#include <shared_mutex>
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
 * @brief Retrieves the last error recorded on this thread.
 *
 * The last error is per-thread: a call that fails on one thread leaves nothing for another thread
 * to read, so it must be retrieved on the thread that made the failing call. This is a pure
 * accessor and does not consume the error; see @ref clear_error.
 *
 * @return The last error recorded on this thread, or an empty string if there is none.
 */
[[nodiscard]]
MPSS_DECOR std::string get_error();

/**
 * @brief Determines whether the last operation on this thread left an error.
 *
 * Equivalent to `!get_error().empty()`, but allocates nothing and cannot throw, so it is safe to
 * call from a `noexcept` context or after an allocation failure. Like @ref get_error, this is a
 * pure accessor: it does not clear the last error.
 *
 * @return true if an error is set, false otherwise.
 */
[[nodiscard]]
MPSS_DECOR bool has_error() noexcept;

/**
 * @brief Clears the last error for this thread.
 *
 * Every fallible MPSS operation clears the last error on entry, apart from @ref KeyPair::release_key,
 * so this is not needed to keep one call's error from leaking into the next.
 *
 * It is for marking an error as handled. Since @ref get_error does not consume the error, an outer
 * layer that inspects it cannot tell an error an inner layer already reported from a fresh one.
 * Clearing it once handled keeps it from being reported twice. Entering another MPSS call does not
 * substitute for this, as the error must survive until whoever handles it has run.
 */
MPSS_DECOR void clear_error() noexcept;

/**
 * @brief Determines whether the given signature algorithm is available in the default backend.
 *
 * What "available" means is decided by the backend and is not uniform across backends. A backend may
 * answer by probing at runtime -- creating a scratch key, signing with it and deleting it -- in which
 * case a true result means creation and signing worked at that moment. A backend may instead answer
 * from static capability, in which case a true result means only that the backend implements the
 * algorithm and says nothing about whether its device is attached or usable. The YubiKey backend
 * answers statically and so reports availability with no device present; the operating-system backends
 * probe. Treat a true result as "worth attempting", not as a guarantee that the next call will succeed.
 *
 * A true result is cached for the remainder of the process; a false one is not, so a transient failure
 * does not become permanent.
 *
 * @param algorithm The signature algorithm to check.
 * @return true if the algorithm is available, false otherwise. @ref has_error is set only when the
 * query could not be dispatched at all, that is, when the algorithm is unknown or no backend could be
 * selected. Once a backend answers, the answer is reported without an error, so a probe that failed
 * because the device was locked or busy is indistinguishable from a genuine negative. That is why a
 * false result is never cached.
 */
[[nodiscard]]
MPSS_DECOR bool is_algorithm_available(Algorithm algorithm);

/**
 * @brief Determines whether the given signature algorithm is available in a specific backend.
 *
 * The meaning of "available" is the named backend's; see @ref is_algorithm_available(Algorithm).
 *
 * @param algorithm The signature algorithm to check.
 * @param backend_name The backend to check (e.g., "os", "yubikey").
 * @return true if the algorithm is available, false otherwise. @ref has_error is set only when the
 * query could not be dispatched at all, that is, when the algorithm is unknown or the named backend
 * does not exist. Once the backend answers, the answer is reported without an error.
 */
[[nodiscard]]
MPSS_DECOR bool is_algorithm_available(Algorithm algorithm, std::string_view backend_name);

/**
 * @brief Returns all signature algorithms available in the default backend.
 *
 * Each algorithm is decided by @ref is_algorithm_available(Algorithm) and inherits its meaning of
 * "available".
 *
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
MPSS_DECOR std::vector<const char *> get_available_backends();

/**
 * @brief Lists currently reachable selectable device identifiers for a backend.
 *
 * An empty list is a successful snapshot without selectable devices; OS storage has no device
 * selectors. A nullopt reports an enumeration or dispatch failure through @ref get_error.
 */
[[nodiscard]]
MPSS_DECOR std::optional<std::vector<std::string>> get_available_devices(std::string_view backend_name);

/**
 * @brief Get the name of the default backend.
 * @return The default backend name, or an empty string if none is available.
 */
[[nodiscard]]
MPSS_DECOR const char *get_default_backend_name();

/**
 * @brief Represents a handle to a key pair in the safe storage system.
 *
 * A handle is safe to use from several threads at once. Signing, verifying and extracting may run
 * concurrently with each other, while releasing and deleting exclude everything else, so an
 * operation either runs wholly before a release or is refused by it. Destroying a handle is not an
 * operation: like any other object, it must not be destroyed while another thread is using it.
 *
 * Overloads taking a key name use the backend's environment defaults. Overloads taking a
 * KeyLocation use the supplied backend and device selection instead. Once a key is opened or
 * created, changing those defaults does not change which device its handle uses.
 */
class MPSS_DECOR KeyPair
{
    friend class impl::BackendNameSetter;

  public:
    KeyPair() = delete;

    virtual ~KeyPair();

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
    const char *backend_name() const noexcept
    {
        return backend_name_;
    }

    /**
     * @brief Returns the actual location recorded when this handle was created or opened.
     *
     * YubiKey device identifiers are canonical decimal serial numbers. OS storage has no device
     * identifier. This immutable metadata remains available after releasing the handle.
     */
    [[nodiscard]]
    KeyLocation location() const;

    /**
     * @brief Creates a key at an explicitly selected backend.
     *
     * Leave the device ID unset for automatic selection, without using MPSS_YUBIKEY_SERIAL.
     * A supplied ID must be nonempty and supported by the backend; another device is never substituted.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Create(const KeyLocation &location, Algorithm algorithm,
                                           KeyPolicy policy = KeyPolicy::none);

    /** @brief Opens a location using the same device-selection rules as @ref Create. */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Open(const KeyLocation &location);

    /** @brief Clears every key under the name in the selected storage, without falling back. */
    [[nodiscard]]
    static bool Delete(const KeyLocation &location);

    /**
     * @brief Creates a new key pair with the given name and algorithm.
     * @param[in] name The name of the key pair. Must be 1-64 printable ASCII characters (0x20-0x7E);
     * control characters, embedded NUL, and non-ASCII bytes are rejected.
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
     * @param[in] name The name of the key pair. Must be 1-64 printable ASCII characters (0x20-0x7E);
     * control characters, embedded NUL, and non-ASCII bytes are rejected.
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
     * @param[in] name The name of the key pair to open. Must be 1-64 printable ASCII characters
     * (0x20-0x7E); control characters, embedded NUL, and non-ASCII bytes are rejected.
     * @return Key pair instance if the key pair was opened successfully, a null pointer
     * otherwise.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Open(std::string_view name);

    /**
     * @brief Opens the key pair with the given name using a specific backend.
     * @param[in] name The name of the key pair to open. Must be 1-64 printable ASCII characters
     * (0x20-0x7E); control characters, embedded NUL, and non-ASCII bytes are rejected.
     * @param[in] backend_name The backend to use (e.g., "os", "yubikey").
     * @return Key pair if opened successfully, nullptr otherwise.
     */
    [[nodiscard]]
    static std::unique_ptr<KeyPair> Open(std::string_view name, std::string_view backend_name);

    /**
     * @brief Deletes every key stored under the given name.
     * @param[in] name The name to clear. Must be 1-64 printable ASCII characters (0x20-0x7E);
     * control characters, embedded NUL, and non-ASCII bytes are rejected.
     * @return true if the name holds no key afterwards, false if something could not be removed or
     * the storage could not be read.
     * @note Unlike @ref delete_key, this needs no open key pair and does not require the name to
     * resolve to a single usable key, so it can clear a name that @ref Open refuses as ambiguous.
     * Every key under the name is removed: leaving one behind would let a name that @ref Open
     * refused start resolving again, to whichever key happened to survive. A name that holds
     * nothing is already in the requested state and succeeds.
     * @note Only the default backend is cleared; use the overload taking a backend name to clear a
     * different one. A failure may be partial, because clearing continues past a source that could
     * not be cleared, so treat the name as unsafe to reuse until a later call succeeds.
     */
    [[nodiscard]]
    static bool Delete(std::string_view name);

    /**
     * @brief Deletes every key stored under the given name in a specific backend.
     * @param[in] name The name to clear. Must be 1-64 printable ASCII characters (0x20-0x7E);
     * control characters, embedded NUL, and non-ASCII bytes are rejected.
     * @param[in] backend_name The backend to clear the name in (e.g., "os", "yubikey").
     * @return true if the name holds no key afterwards, false if something could not be removed or
     * the storage could not be read.
     */
    [[nodiscard]]
    static bool Delete(std::string_view name, std::string_view backend_name);

    /**
     * @brief Deletes the key pair with the given name from the safe storage.
     * @return true if the key pair was deleted successfully, false otherwise.
     * @note After this function returns successfully, the key pair handle is no longer valid, in
     * the same sense as @ref release_key: every operation on it fails, and it cannot reach a key
     * created later under the same name.
     */
    bool delete_key();

    /**
     * @brief Signs the given hash data with the key pair.
     * @param[in] hash The hash to sign.
     * @param[in,out] sig A buffer where the signature is written.
     * @return If sig is empty, returns the number of bytes required in sig to hold the
     * signature. Otherwise, returns the number of bytes written to sig. Returns 0 if the
     * operation failed.
     */
    [[nodiscard]]
    std::size_t sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const;

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
    bool verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const;

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
    std::size_t extract_key(std::span<std::byte> public_key) const;

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
     * instance is destroyed. After calling this function, the key pair handle is no longer valid: every operation
     * on it fails, including the size requests spelled as @ref sign_hash and @ref extract_key with an empty
     * buffer, and releasing it again does nothing. The algorithm, the key information, @ref sign_hash_size and
     * @ref extract_key_size still answer, since those are derived from what the handle recorded when it was
     * opened rather than from the key itself.
     *
     * The handle is invalidated whether or not the release succeeds, so a false return reports that something the
     * handle held could not be given up rather than inviting another attempt. Releasing an already released handle
     * repeats what the one attempt reported, and describes it through @ref get_error only on the thread that made
     * it. Ignoring the answer is expected, which is why this is not [[nodiscard]].
     * @return True if everything the handle held was released, false otherwise, in which case @ref get_error
     * describes the failure.
     */
    bool release_key();

  protected:
    // NOLINTBEGIN(*-non-private-member-variables-in-classes) - subclasses need direct access.
    Algorithm algorithm_;
    AlgorithmInfo info_;
    KeyInfo key_info_;
    const char *backend_name_{""};
    std::optional<std::string> device_id_;

    // NOLINTEND(*-non-private-member-variables-in-classes)

    KeyPair(Algorithm algorithm, StorageTier storage_tier);

    // Releases the handle on the way out of a backend destructor, which is the only place it can
    // happen: once ~KeyPair runs, the backend is gone and do_release_key no longer resolves to it.
    // Every backend destructor must call this. Swallows what a release reports, since a destructor
    // must not propagate an exception and there is nobody left to tell.
    void release_from_destructor() noexcept;

    // Non-virtual interface. Each public operation above clears the last error, validates its
    // inputs and refuses a released handle before dispatching to one of the implementations
    // below. Releasing is the exception: it latches rather than refusing, and leaves the last
    // error alone.

    virtual bool do_delete_key() = 0;

    // Releases whatever the handle holds and reports whether it could. Called at most once per
    // handle, so an implementation needs no guard of its own, and may report success without doing
    // anything where there is nothing to release.
    virtual bool do_release_key() = 0;

    [[nodiscard]]
    virtual std::size_t do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const = 0;

    [[nodiscard]]
    virtual bool do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const = 0;

    [[nodiscard]]
    virtual std::size_t do_extract_key(std::span<std::byte> public_key) const = 0;

  private:
    // Releases the handle, with mtx_ already held exclusively. Deleting releases the handle it
    // deleted through, and cannot reach release_key() to do it without deadlocking.
    bool release_locked();

    // Operations take this in shared mode and run concurrently; releasing and deleting take it
    // exclusively, which is what keeps the latch below a single decision rather than a check and a
    // set that another thread can land between.
    mutable std::shared_mutex mtx_;

    bool released_{false};
    bool release_result_{true};
    std::string key_name_;
};

} // namespace mpss
