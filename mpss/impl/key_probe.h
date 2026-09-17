// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

namespace mpss::impl
{

/**
 * @brief Outcome of looking up a key by name in a backing store.
 *
 * A lookup has three outcomes, not two. Collapsing @ref not_found and @ref operational_error into a
 * single "no key" answer makes a name that could not be ruled out indistinguishable from a name that
 * was ruled out. Backends that report this distinction let creation refuse to proceed when the name
 * was never established to be free, because a key of the same name may already be present.
 */
enum class KeyProbeStatus
{
    /** @brief The store was queried and holds a usable key with this name. */
    found,

    /** @brief The store was queried and holds no key with this name. */
    not_found,

    /**
     * @brief The lookup produced no usable key and did not rule the name out.
     *
     * This covers a store that could not be queried at all, and a key that was located but cannot be
     * used -- one whose algorithm this backend does not support, for instance. The two differ in
     * whether presence is known, but they agree on what the caller may do: the name was never
     * established to be free, so creating a key under it risks replacing or shadowing one already
     * there, depending on how the backend places keys.
     *
     * The last error describes the failure.
     */
    operational_error
};

/**
 * @brief A @ref KeyProbeStatus paired with whatever the backend recovered about the key.
 *
 * @p value is meaningful only when @p status is KeyProbeStatus::found.
 *
 * @tparam T Backend-specific description of the key that was found.
 */
template <typename T> struct KeyProbeResult
{
    /** @brief Whether the key was found, absent, or could not be determined. */
    KeyProbeStatus status;

    /** @brief What the backend recovered about the key. Only valid when @p status is found. */
    T value;
};

} // namespace mpss::impl
