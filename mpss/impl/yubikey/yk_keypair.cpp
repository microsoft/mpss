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

YubiKeyKeyPair::YubiKeyKeyPair(std::string_view name, Algorithm algorithm, std::uint8_t slot, std::uint32_t serial)
    : KeyPair{algorithm, /* hardware_backed */ true, "YubiKey PIV"}, name_{name}, slot_{slot}, serial_{serial}
{
}

bool YubiKeyKeyPair::do_delete_key()
{
    mpss::utils::log_trace("Deleting YubiKey key '{}' in slot {}.", name_, utils::get_slot_name(slot_));
    YubiKeyPIV piv{serial_};
    if (!piv.is_connected())
    {
        mpss::utils::log_trace("Cannot delete key '{}': YubiKey connection failed.", name_);
        return false;
    }

    // Try deleting without PIN authentication first (succeeds when the management key is available without PIN,
    // e.g., via MPSS_YUBIKEY_MGM_KEY or the explicitly enabled factory default).
    YubiKeyPIV::DeleteResult deleted = piv.delete_key(slot_);

    if (YubiKeyPIV::DeleteResult::unauthenticated == deleted)
    {
        // Wanting credentials is the one refusal a PIN can settle, because the management key may be
        // PIN-protected. Every other refusal stands on grounds no PIN satisfies, so prompting there
        // would spend an attempt on a retry that can only fail the same way.
        if (!authenticate_pin_interactive(piv, "delete key '" + name_ + "'"))
        {
            mpss::utils::log_trace("Cannot delete key '{}': PIN authentication failed.", name_);
            return false;
        }

        // PIN is now verified on this connection.
        deleted = piv.delete_key(slot_);
    }

    if (YubiKeyPIV::DeleteResult::deleted == deleted)
    {
        mpss::utils::log_trace("Key '{}' in slot {} deleted.", name_, utils::get_slot_name(slot_));
        return true;
    }

    mpss::utils::log_trace("Failed to delete key '{}' from slot {}.", name_, utils::get_slot_name(slot_));
    return false;
}

std::size_t YubiKeyKeyPair::do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    mpss::utils::log_trace("Signing hash with YubiKey key '{}' in slot {}, hash size {}.", name_,
                           utils::get_slot_name(slot_), hash.size());

    YubiKeyPIV piv{serial_};
    if (!piv.is_connected())
    {
        mpss::utils::log_trace("Cannot sign with key '{}': YubiKey connection failed.", name_);
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
            const std::size_t written = piv.sign(slot_, hash, algorithm(), sig, /* probe */ true);
            if (0 != written)
            {
                return written;
            }
        }

        // Either the key has a touch policy (so we don't probe with sign()) or the sign() probe indicated that PIN
        // is needed. In either case, we authenticate the PIN now.
        if (!authenticate_pin_interactive(piv, "sign with key '" + name_ + "'"))
        {
            mpss::utils::log_trace("Cannot sign with key '{}': PIN authentication failed.", name_);
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
        handler->notify_touch_complete(0 != written);
    }

    if (0 != written)
    {
        mpss::utils::log_trace("YubiKey sign produced {} byte signature.", written);
    }
    else
    {
        mpss::utils::log_trace("YubiKey sign failed for key '{}' in slot {}.", name_, utils::get_slot_name(slot_));
    }

    return written;
}

bool YubiKeyKeyPair::do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    // Extract public key and do software verification.
    const std::size_t expected_public_key_size = mpss::utils::get_public_key_size(algorithm());
    std::vector<std::byte> public_key(expected_public_key_size);
    const std::size_t pk_len = extract_key(public_key);
    if (0 == pk_len)
    {
        mpss::utils::log_and_set_error("Cannot verify with key '{}': public key extraction failed.", name_);
        return false;
    }
    public_key.resize(pk_len);

    // Use standalone verification using OpenSSL.
    const bool verified = mpss::verify(hash, public_key, algorithm(), sig);
    if (!verified)
    {
        mpss::utils::log_trace("Signature verification failed for key '{}'.", name_);
    }
    return verified;
}

std::size_t YubiKeyKeyPair::do_extract_key(std::span<std::byte> public_key) const
{
    // Connect and extract public key directly into the caller's buffer.
    mpss::utils::log_trace("Extracting public key from YubiKey slot {}.", utils::get_slot_name(slot_));
    YubiKeyPIV piv{serial_};
    if (!piv.is_connected())
    {
        mpss::utils::log_trace("Cannot extract public key for '{}': YubiKey connection failed.", name_);
        return 0;
    }

    const std::size_t pk_size = piv.get_public_key(slot_, public_key);
    if (0 != pk_size)
    {
        mpss::utils::log_trace("Extracted {} byte public key from YubiKey slot {}.", pk_size,
                               utils::get_slot_name(slot_));
    }
    else
    {
        mpss::utils::log_trace("Failed to extract public key from slot {} for key '{}'.", utils::get_slot_name(slot_),
                               name_);
    }
    return pk_size;
}

bool YubiKeyKeyPair::do_release_key()
{
    // Nothing to do here. Connections are managed per operation.
    return true;
}

} // namespace mpss::impl::yubikey
