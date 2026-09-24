// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_keypair.h"
#include "mpss/impl/yubikey/yk_piv.h"
#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/interaction_handler.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <mutex>
#include <vector>
#include <ykpiv/ykpiv.h>

namespace mpss::impl::yubikey
{

YubiKeyKeyPair::YubiKeyKeyPair(std::string_view name, Algorithm algorithm, std::uint8_t slot, std::uint32_t serial,
                               std::span<const std::byte> public_key)
    : KeyPair{algorithm, StorageTier::yubikey_piv}, name_{name}, slot_{slot}, serial_{serial},
      public_key_{public_key.begin(), public_key.end()}
{
    device_id_ = std::to_string(serial);
}

bool YubiKeyKeyPair::is_opened_key(std::span<const std::byte> slot_key) const
{
    if (public_key_.empty() || !std::ranges::equal(public_key_, slot_key))
    {
        mpss::utils::log_and_set_error("Key '{}' is no longer the key this handle opened.", name_);
        return false;
    }
    return true;
}

bool YubiKeyKeyPair::slot_still_holds_opened_key(YubiKeyPIV &piv) const
{
    std::vector<std::byte> slot_key(mpss::utils::get_public_key_size(algorithm()));
    const std::size_t read = piv.get_public_key(slot_, slot_key, /* probe */ true);
    if (0 == read)
    {
        // An emptied slot reads as nothing, which is as much a replacement as a different key.
        mpss::utils::log_and_set_error("Key '{}' is no longer the key this handle opened.", name_);
        return false;
    }
    return is_opened_key(std::span<const std::byte>{slot_key}.first(read));
}

bool YubiKeyKeyPair::do_delete_key()
{
    // Held for the same reason the lifecycle entry points hold it: checking that the name still
    // holds what this handle opened, and then deleting it, must be one decision.
    const std::scoped_lock lifecycle{mpss::utils::name_mutex(name_)};

    mpss::utils::log_trace("Deleting YubiKey key '{}' in slot {}.", name_, utils::get_slot_name(slot_));
    YubiKeyPIV piv{serial_, name_, public_key_, slot_};
    if (!piv.is_connected())
    {
        mpss::utils::log_trace("Cannot delete key '{}': YubiKey connection failed.", name_);
        return false;
    }

    // Checked before anything is deleted, so that deleting through a handle whose key has been
    // replaced cannot destroy the key that replaced it.
    if (!slot_still_holds_opened_key(piv))
    {
        return false;
    }

    // Try deleting without PIN authentication first (succeeds when the management key is available without PIN,
    // e.g., via MPSS_YUBIKEY_MGM_KEY or the explicitly enabled factory default).
    YubiKeyPIV::DeleteResult deleted = piv.delete_key(slot_, /* probe */ true);

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

        // PIN is now verified on this connection. The slot is confirmed again because the prompt
        // above waits on a person, which is long enough for another writer to take the slot over
        // between the first check and this delete.
        if (!slot_still_holds_opened_key(piv))
        {
            return false;
        }

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

    YubiKeyPIV piv{serial_, name_, public_key_, slot_};
    if (!piv.is_connected())
    {
        mpss::utils::log_trace("Cannot sign with key '{}': YubiKey connection failed.", name_);
        return 0;
    }

    // Checked before any PIN or touch is asked for, so a handle whose key has been replaced spends
    // neither. One read answers all three questions signing asks of the slot.
    YubiKeyPIV::SlotMetadata metadata;
    if (!piv.read_slot_metadata(slot_, metadata, /* probe */ true))
    {
        // A slot that will not answer no longer holds the key this handle opened, as far as this
        // operation can tell.
        mpss::utils::log_and_set_error("Key '{}' is no longer the key this handle opened.", name_);
        return 0;
    }
    if (!is_opened_key(metadata.public_key))
    {
        return 0;
    }

    const std::shared_ptr<InteractionHandler> handler = mpss::GetInteractionHandler();
    const bool needs_pin = (YKPIV_PINPOLICY_NEVER != metadata.pin_policy);
    const bool needs_touch = (YKPIV_TOUCHPOLICY_NEVER != metadata.touch_policy);

    // Closing a connection resets the card, so no PIN verified by an earlier operation survives to here.
    if (needs_pin)
    {
        if (!authenticate_pin_interactive(piv, "sign with key '" + name_ + "'"))
        {
            mpss::utils::log_trace("Cannot sign with key '{}': PIN authentication failed.", name_);
            return 0;
        }

        // The prompt above waits on a person, which is long enough for another writer to take the
        // slot over, so what it holds is confirmed again before this signs with it.
        if (!slot_still_holds_opened_key(piv))
        {
            return 0;
        }
    }

    // PIN is now authenticated (or wasn't needed). Sign may block waiting for touch if the key has a touch policy.
    if (needs_touch)
    {
        const mpss::utils::InteractionHandlerScope in_handler;
        handler->notify_touch_needed(piv.interaction_context());
    }

    const std::size_t written = piv.sign(slot_, hash, algorithm(), sig);

    if (needs_touch)
    {
        const mpss::utils::InteractionHandlerScope in_handler;
        handler->notify_touch_complete(piv.interaction_context(), 0 != written);
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
    // do_extract_key rather than extract_key: the public entry point takes the handle lock that
    // verifying already holds, and that lock is not recursive.
    const std::size_t pk_len = do_extract_key(public_key);
    if (0 == pk_len)
    {
        // Extraction refuses a handle whose key has been replaced, and says so; that reason is
        // more use to the caller than this one.
        if (!mpss::utils::has_error())
        {
            mpss::utils::log_and_set_error("Cannot verify with key '{}': public key extraction failed.", name_);
        }
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
    mpss::utils::log_trace("Extracting public key from YubiKey slot {}.", utils::get_slot_name(slot_));
    YubiKeyPIV piv{serial_, name_, public_key_, slot_};
    if (!piv.is_connected())
    {
        mpss::utils::log_trace("Cannot extract public key for '{}': YubiKey connection failed.", name_);
        return 0;
    }

    // Read into a temporary: a failed extraction must leave the caller's buffer untouched, and a
    // slot that has moved on would otherwise hand back the key that replaced the one opened here.
    std::vector<std::byte> slot_key(mpss::utils::get_public_key_size(algorithm()));
    const std::size_t pk_size = piv.get_public_key(slot_, slot_key);
    if (0 == pk_size)
    {
        mpss::utils::log_trace("Failed to extract public key from slot {} for key '{}'.", utils::get_slot_name(slot_),
                               name_);
        return 0;
    }

    if (!is_opened_key(std::span<const std::byte>{slot_key}.first(pk_size)))
    {
        return 0;
    }

    if (pk_size > public_key.size())
    {
        mpss::utils::log_and_set_error("Public key buffer too small.");
        return 0;
    }
    std::copy_n(slot_key.begin(), pk_size, public_key.begin());

    mpss::utils::log_trace("Extracted {} byte public key from YubiKey slot {}.", pk_size, utils::get_slot_name(slot_));
    return pk_size;
}

bool YubiKeyKeyPair::do_release_key()
{
    // Nothing to do here. Connections are managed per operation.
    return true;
}

} // namespace mpss::impl::yubikey
