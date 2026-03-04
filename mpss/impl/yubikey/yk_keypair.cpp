// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_keypair.h"
#include "mpss/impl/yubikey/yk_piv.h"
#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/interaction_handler.h"
#include "mpss/utils/utilities.h"
#include <ykpiv/ykpiv.h>

namespace mpss::impl::yubikey
{

YubiKeyKeyPair::YubiKeyKeyPair(std::string_view name, Algorithm algorithm, std::uint8_t slot)
    : KeyPair{algorithm, /* hardware_backed */ true, "YubiKey PIV"}, name_{name}, slot_{slot}
{
}

bool YubiKeyKeyPair::delete_key()
{
    mpss::utils::log_trace("Deleting YubiKey key '{}' in slot {}.", name_, utils::get_slot_name(slot_));
    YubiKeyPIV piv;
    if (!piv.is_connected())
    {
        return false;
    }

    // Try deleting without PIN authentication first (succeeds when the management key is available without PIN,
    // e.g., via MPSS_YUBIKEY_MGM_KEY or the factory default).
    bool deleted = piv.delete_key(slot_);

    if (!deleted)
    {
        // Deletion failed. We likely need the PIN for management key access.
        if (!authenticate_pin_interactive(piv, "delete key '" + name_ + "'"))
        {
            return false;
        }

        // PIN is now verified on this connection.
        deleted = piv.delete_key(slot_);
    }

    if (deleted)
    {
        mpss::utils::log_trace("Key '{}' in slot {} deleted.", name_, utils::get_slot_name(slot_));
    }
    return deleted;
}

std::size_t YubiKeyKeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    if (sig.empty())
    {
        // If the signature buffer is empty, we want to return the size of the signature.
        return mpss::utils::get_max_signature_size(algorithm());
    }

    mpss::utils::log_trace("Signing hash with YubiKey key '{}' in slot {}, hash size {}.", name_,
                           utils::get_slot_name(slot_), hash.size());

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!mpss::utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }

    YubiKeyPIV piv;
    if (!piv.is_connected())
    {
        return 0;
    }

    const std::shared_ptr<InteractionHandler> handler = mpss::GetInteractionHandler();
    const bool needs_pin = (YKPIV_PINPOLICY_NEVER != piv.get_key_pin_policy(slot_));
    const bool needs_touch = (YKPIV_TOUCHPOLICY_NEVER != piv.get_key_touch_policy(slot_));

    // The logic is a bit complicated by the fact that we want to avoid unnecessary PIN prompts, but also avoid
    // using sign() as a probe when the key has a touch policy (to prevent unexpected blocking waiting for touch).
    // The rules are:
    // - If the key has a touch policy, authenticate PIN upfront if needed, then call sign() directly (which may
    // block for touch).
    // - If the key has no touch policy, we can use sign() as a probe to check if PIN authentication is needed (it
    // returns an empty signature if PIN is required but not authenticated). This allows us to avoid unnecessary
    // PIN prompts when the PIN is already cached from a prior session.
    if (needs_pin)
    {
        if (!needs_touch)
        {
            // No touch policy, so sign() returns instantly. Use it as a probe to check whether PIN authentication
            // is actually needed (it may already be cached).
            const std::size_t written = piv.sign(slot_, hash, algorithm(), sig);
            if (0 != written)
            {
                return written;
            }
        }

        // Either the key has a touch policy (so we don't probe with sign()) or the sign() probe indicated that PIN
        // is needed. In either case, we authenticate the PIN now.
        if (!authenticate_pin_interactive(piv, "sign with key '" + name_ + "'"))
        {
            return 0;
        }
    }

    // PIN is now authenticated (or wasn't needed). Sign may block waiting for touch if the key has a touch policy.
    if (needs_touch)
    {
        handler->notify_touch_needed();
    }

    const std::size_t written = piv.sign(slot_, hash, algorithm(), sig);

    if (needs_touch)
    {
        handler->notify_touch_complete();
    }

    if (0 != written)
    {
        mpss::utils::log_trace("YubiKey sign produced {} byte signature.", written);
    }

    return written;
}

bool YubiKeyKeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    if (hash.empty() || sig.empty())
    {
        mpss::utils::log_warning("Nothing to verify.");
        return false;
    }

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }

    // Extract public key and do software verification.
    const std::size_t expected_public_key_size = mpss::utils::get_public_key_size(algorithm());
    std::vector<std::byte> public_key(expected_public_key_size);
    const std::size_t pk_len = extract_key(public_key);
    if (0 == pk_len)
    {
        return false;
    }
    public_key.resize(pk_len);

    // Use standalone verification using OpenSSL.
    return mpss::verify(hash, public_key, algorithm(), sig);
}

std::size_t YubiKeyKeyPair::extract_key(std::span<std::byte> public_key) const
{
    if (public_key.empty())
    {
        return mpss::utils::get_public_key_size(algorithm());
    }
    else if (!mpss::utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }

    // Connect and extract public key directly into the caller's buffer.
    mpss::utils::log_trace("Extracting public key from YubiKey slot {}.", utils::get_slot_name(slot_));
    YubiKeyPIV piv;
    if (!piv.is_connected())
    {
        return 0;
    }

    const std::size_t pk_size = piv.get_public_key(slot_, public_key);
    if (0 != pk_size)
    {
        mpss::utils::log_trace("Extracted {} byte public key from YubiKey slot {}.", pk_size,
                               utils::get_slot_name(slot_));
    }
    return pk_size;
}

void YubiKeyKeyPair::release_key()
{
    // Nothing to do here. Connections are managed per operation.
}

} // namespace mpss::impl::yubikey
