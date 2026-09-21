// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_backend.h"
#include "mpss/impl/yubikey/yk_keypair.h"
#include "mpss/impl/yubikey/yk_piv.h"
#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>

namespace
{

// Software ECDSA verification using OpenSSL. Distinguishes a clean signature mismatch from an
// operational failure so callers can keep the last-error channel meaningful.
enum class VerifyOutcome
{
    verified,
    mismatch,
    error
};

VerifyOutcome openssl_ecdsa_verify(const char *group_name, std::span<const std::byte> hash,
                                   std::span<const std::byte> public_key, std::span<const std::byte> sig)
{
    using enum VerifyOutcome;

    // Build an EVP_PKEY from the raw uncompressed EC point (X9.63: 04||X||Y).
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char *>(group_name), 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(public_key.data())), public_key.size()),
        OSSL_PARAM_END};

    EVP_PKEY_CTX *build_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (nullptr == build_ctx)
    {
        return error;
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_fromdata_init(build_ctx) <= 0 || EVP_PKEY_fromdata(build_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        EVP_PKEY_CTX_free(build_ctx);
        return error;
    }
    EVP_PKEY_CTX_free(build_ctx);
    SCOPE_GUARD(EVP_PKEY_free(pkey));

    // Verify the DER-encoded ECDSA signature against the pre-computed hash.
    EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (nullptr == verify_ctx)
    {
        return error;
    }
    SCOPE_GUARD(EVP_PKEY_CTX_free(verify_ctx));

    if (EVP_PKEY_verify_init(verify_ctx) <= 0)
    {
        return error;
    }

    const int result = EVP_PKEY_verify(verify_ctx, reinterpret_cast<const unsigned char *>(sig.data()), sig.size(),
                                       reinterpret_cast<const unsigned char *>(hash.data()), hash.size());
    if (1 == result)
    {
        return verified;
    }
    if (0 == result)
    {
        return mismatch;
    }
    return error;
}

} // namespace

namespace mpss::impl::yubikey
{

using enum Algorithm;

const char *YubiKeyBackend::name() const
{
    return "yubikey";
}

bool YubiKeyBackend::is_algorithm_available(Algorithm algorithm) const
{
    return 0 != utils::mpss_to_yk_algorithm(algorithm);
}

std::unique_ptr<KeyPair> YubiKeyBackend::create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy) const
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (is_reserved_key_name(name))
    {
        mpss::utils::log_and_set_error("Key name '{}' is reserved.", key_name);
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    const std::uint8_t yk_algorithm = utils::mpss_to_yk_algorithm(algorithm);
    if (0 == yk_algorithm)
    {
        // Algorithm is not supported by YubiKey.
        mpss::utils::log_and_set_error("Algorithm not supported by YubiKey PIV.");
        return nullptr;
    }

    constexpr std::uint64_t supported_policy = static_cast<std::uint64_t>(yubikey_pin_mask | yubikey_touch_mask);
    const std::uint64_t raw_policy = static_cast<std::uint64_t>(policy);
    const std::uint64_t pin_policy = raw_policy & static_cast<std::uint64_t>(yubikey_pin_mask);
    const std::uint64_t touch_policy = (raw_policy & static_cast<std::uint64_t>(yubikey_touch_mask)) >> 4U;
    if (0 != (raw_policy & ~supported_policy) || 3U < pin_policy || 3U < touch_policy)
    {
        mpss::utils::log_and_set_error("YubiKey backend does not support the requested key policy.");
        return nullptr;
    }

    // Determine which YubiKey to target.
    bool device_skipped = false;
    const std::optional<std::uint32_t> target_serial = utils::get_serial_from_env();
    const std::vector<std::uint32_t> serials =
        target_serial ? std::vector<std::uint32_t>{*target_serial} : YubiKeyPIV::available_serials(&device_skipped);

    // A device left out of the list is a device the refusal below cannot count, so a key would be
    // created on whichever one happened to answer. Asked first, for the same reason it is asked
    // first when clearing a name.
    if (!target_serial && device_skipped)
    {
        mpss::utils::log_and_set_error("Refusing to create key '{}': an attached YubiKey could not be identified. Set "
                                       "MPSS_YUBIKEY_SERIAL to select the target device.",
                                       key_name);
        return nullptr;
    }

    // Refuse to create a key when multiple YubiKeys are present and no serial is specified,
    // since the caller cannot control which device receives the key.
    if (!target_serial && serials.size() > 1)
    {
        mpss::utils::log_and_set_error(
            "Multiple YubiKeys detected. Set MPSS_YUBIKEY_SERIAL to select the target device.");
        return nullptr;
    }

    if (serials.empty())
    {
        mpss::utils::log_and_set_error("No YubiKey found.");
        return nullptr;
    }

    // Connect to YubiKey.
    mpss::utils::log_trace("Creating key '{}' with algorithm '{}' on YubiKey.", key_name,
                           get_algorithm_info(algorithm).type_str);
    YubiKeyPIV piv{serials.front()};
    if (!piv.is_connected())
    {
        return nullptr;
    }

    // Check if key already exists on the device. A scan that could not rule the name out must not create, or the
    // device could end up with two slots carrying the same name.
    const KeyProbeResult<YubiKeyPIV::SlotInfo> existing = piv.find_slot_by_name(name);
    if (KeyProbeStatus::operational_error == existing.status)
    {
        return nullptr;
    }
    if (KeyProbeStatus::found == existing.status)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    // Find a free slot.
    const std::uint8_t slot = piv.find_free_slot();
    if (0 == slot)
    {
        mpss::utils::log_and_set_error("No free PIV slots available on YubiKey.");
        return nullptr;
    }

    // Try generating the key without PIN authentication first (succeeds when the management key is available
    // without PIN, e.g., via MPSS_YUBIKEY_MGM_KEY or the explicitly enabled factory default).
    std::vector<std::byte> generated_public_key;
    YubiKeyPIV::GenerateResult generated = piv.generate_key(slot, yk_algorithm, policy, &generated_public_key);

    if (YubiKeyPIV::GenerateResult::unauthenticated == generated)
    {
        // Wanting credentials is the one refusal a PIN can settle, because the management key may be
        // PIN-protected. Every other refusal stands on grounds no PIN satisfies -- a YubiKey FIPS
        // device outside FIPS-approved mode is the known case -- so prompting there would spend an
        // attempt, and the caller's attention, on a retry that can only fail the same way.
        if (!authenticate_pin_interactive(piv, "generate key '" + key_name + "'"))
        {
            return nullptr;
        }

        // PIN is already verified on this connection.
        generated = piv.generate_key(slot, yk_algorithm, policy, &generated_public_key);
    }

    if (YubiKeyPIV::GenerateResult::generated != generated)
    {
        return nullptr;
    }

    // Write the key name label to the slot's certificate object.
    if (!piv.write_slot_label(slot, name))
    {
        mpss::utils::log_and_set_error("Failed to write the name label for key '{}'.", key_name);
        // Clean up: delete the generated key since we can't label it. Firmware that supports erasure
        // destroys the key; older firmware overwrites it and writes a marker certificate indicating
        // the slot is free. If cleanup itself fails, the slot holds an unlabeled key that MPSS won't
        // find by name, but the slot is consumed until manually cleared.
        if (YubiKeyPIV::DeleteResult::deleted != piv.delete_key(slot))
        {
            mpss::utils::log_warning("Failed to clean up slot {} after labeling failure.", utils::get_slot_name(slot));
        }
        return nullptr;
    }

    // The create sequence (find free slot -> generate -> label) is not a single PC/SC transaction,
    // so a concurrent PIV writer could have taken this slot in between. Re-resolve the name and fail
    // closed rather than hand back a key that may already have been overwritten.
    const KeyProbeResult<YubiKeyPIV::SlotInfo> confirm = piv.find_slot_by_name(name);
    if (KeyProbeStatus::found != confirm.status || confirm.value.slot != slot || confirm.value.algorithm != algorithm)
    {
        // Remove the key just generated, so a name that two writers reached at once does not stay
        // ambiguous and consume a slot. Roll back only while this slot still carries this name: a
        // slot another writer has since taken over holds their key, which is not ours to delete.
        const KeyProbeResult<std::string> own_label = piv.read_slot_label(slot);
        if (KeyProbeStatus::found == own_label.status && own_label.value == key_name &&
            YubiKeyPIV::DeleteResult::deleted != piv.delete_key(slot))
        {
            mpss::utils::log_warning("Failed to clean up slot {} after a concurrent modification.",
                                     utils::get_slot_name(slot));
        }

        mpss::utils::log_and_set_error("Concurrent modification detected while creating key '{}'; aborting.", key_name);
        return nullptr;
    }

    const std::uint32_t serial = piv.get_serial();

    // The handle is bound to the key this call generated, which is the only thing that identifies
    // it. A slot another writer has filled since holds a different key, and the name, algorithm and
    // origin of that key would all pass the checks above.
    YubiKeyPIV::SlotMetadata slot_metadata;
    if (!piv.read_slot_metadata(slot, slot_metadata))
    {
        // A slot that will not answer and a slot holding a key this code cannot represent, such as
        // one a racing writer imported in an algorithm MPSS does not handle, look the same from
        // here. Deleting would destroy that writer's key, so the slot is left alone and the caller
        // is told the key could not be confirmed. Clearing the name settles a slot left this way.
        mpss::utils::log_warning("Slot {} could not be read back after creating key '{}' and may still hold a key.",
                                 utils::get_slot_name(slot), key_name);
        mpss::utils::log_and_set_error("Failed to read back the public key for new key '{}'.", key_name);
        return nullptr;
    }

    if (generated_public_key.empty() || slot_metadata.public_key != generated_public_key)
    {
        mpss::utils::log_and_set_error("Concurrent modification detected while creating key '{}'; aborting.", key_name);
        return nullptr;
    }

    mpss::utils::log_trace("Key '{}' created in YubiKey slot {} (serial {}).", key_name, utils::get_slot_name(slot),
                           serial);
    return std::make_unique<YubiKeyKeyPair>(name, algorithm, slot, serial, slot_metadata.public_key);
}

std::unique_ptr<KeyPair> YubiKeyBackend::open_key(std::string_view name) const
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (is_reserved_key_name(name))
    {
        mpss::utils::log_and_set_error("Key name '{}' is reserved.", key_name);
        return nullptr;
    }

    mpss::utils::log_trace("Attempting to open key '{}' on YubiKey.", key_name);

    // Determine which YubiKeys to search.
    bool device_skipped = false;
    const std::optional<std::uint32_t> target_serial = utils::get_serial_from_env();
    const std::vector<std::uint32_t> serials =
        target_serial ? std::vector<std::uint32_t>{*target_serial} : YubiKeyPIV::available_serials(&device_skipped);

    // A device left out of the list is a device the refusal below cannot count, so a name held on
    // more than one device would resolve to whichever one answered.
    if (!target_serial && device_skipped)
    {
        mpss::utils::log_and_set_error("Refusing to open key '{}': an attached YubiKey could not be identified. Set "
                                       "MPSS_YUBIKEY_SERIAL to select the target device.",
                                       key_name);
        return nullptr;
    }

    // Refuse to open when multiple YubiKeys are present and no serial is specified.
    if (!target_serial && serials.size() > 1)
    {
        mpss::utils::log_and_set_error(
            "Multiple YubiKeys detected. Set MPSS_YUBIKEY_SERIAL to select the target device.");
        return nullptr;
    }

    // A device we could not query might hold the key, so it cannot be ruled out.
    bool undetermined = false;

    for (const std::uint32_t serial : serials)
    {
        YubiKeyPIV piv{serial};
        if (!piv.is_connected())
        {
            undetermined = true;
            continue;
        }

        const KeyProbeResult<YubiKeyPIV::SlotInfo> slot_info = piv.find_slot_by_name(name);
        if (KeyProbeStatus::operational_error == slot_info.status)
        {
            undetermined = true;
            continue;
        }
        if (KeyProbeStatus::found == slot_info.status)
        {
            // Bound to the key rather than to the slot, so a slot emptied and filled again under
            // this name is not reachable through this handle.
            YubiKeyPIV::SlotMetadata slot_metadata;
            if (!piv.read_slot_metadata(slot_info.value.slot, slot_metadata, /* probe */ true))
            {
                undetermined = true;
                continue;
            }

            // MPSS opens only keys the device generated itself. An imported key sits in the same
            // secure element and reports the same protection, yet whoever imported it still holds
            // the private material, which is the one thing that protection is meant to rule out.
            if (!slot_metadata.generated_on_device)
            {
                mpss::utils::log_and_set_error(
                    "Refusing to open key '{}': the key in slot {} was imported rather than generated on the device.",
                    key_name, utils::get_slot_name(slot_info.value.slot));
                return nullptr;
            }

            mpss::utils::log_trace("Key '{}' found in YubiKey slot {} (serial {}) with algorithm '{}'.", key_name,
                                   utils::get_slot_name(slot_info.value.slot), serial,
                                   get_algorithm_info(slot_info.value.algorithm).type_str);
            return std::make_unique<YubiKeyKeyPair>(name, slot_info.value.algorithm, slot_info.value.slot, serial,
                                                    slot_metadata.public_key);
        }
    }

    if (undetermined)
    {
        mpss::utils::log_and_set_error("Could not determine whether key '{}' is present on the attached YubiKeys.",
                                       key_name);
        return nullptr;
    }

    mpss::utils::log_debug("Key '{}' not found on any YubiKey.", key_name);
    return nullptr;
}

bool YubiKeyBackend::delete_key(std::string_view name) const
{
    const std::string key_name{name};
    if (is_reserved_key_name(name))
    {
        // "(available)" labels a free slot. Clearing it by name would match every free retired slot
        // on the device and drive a PIN prompt for each.
        mpss::utils::log_and_set_error("Key name '{}' is reserved.", key_name);
        return false;
    }

    // A destructive operation must be no less selective about which device it touches than opening
    // is, so the same device-selection rule applies: clear the pinned device, or refuse when more
    // than one is attached and none was pinned.
    bool device_skipped = false;
    const std::optional<std::uint32_t> target_serial = utils::get_serial_from_env();
    const std::vector<std::uint32_t> serials =
        target_serial ? std::vector<std::uint32_t>{*target_serial} : YubiKeyPIV::available_serials(&device_skipped);
    if (device_skipped)
    {
        // A listed reader that yielded no device may be holding one this process cannot reach, so
        // the name cannot be reported cleared everywhere it might be held. Asked before emptiness:
        // an unidentified device is left out of the list, so the sole attached device going
        // unidentified also leaves the list empty, and "no devices found" would then describe the
        // wrong state.
        mpss::utils::log_and_set_error("Refusing to clear key '{}': an attached YubiKey could not be identified.",
                                       key_name);
        return false;
    }
    if (serials.empty())
    {
        mpss::utils::log_and_set_error("No YubiKey devices found.");
        return false;
    }
    if (!target_serial && serials.size() > 1)
    {
        mpss::utils::log_and_set_error(
            "Multiple YubiKeys detected. Set MPSS_YUBIKEY_SERIAL to select the target device.");
        return false;
    }

    // A device that could not be reached might hold the name, so the name cannot be reported as
    // cleared until every attached device has answered.
    bool undetermined = false;
    std::size_t deleted = 0;

    for (const std::uint32_t serial : serials)
    {
        YubiKeyPIV piv{serial};
        if (!piv.is_connected())
        {
            undetermined = true;
            continue;
        }

        YubiKeyPIV::DeleteByNameResult result = piv.delete_keys_by_name(key_name);
        if (result.needs_authentication)
        {
            // Deleting needs the management key, which may need the PIN on this device. Only a refusal
            // for want of credentials is retried: every other one stands on grounds no PIN satisfies,
            // so prompting there would spend an attempt, and the caller's attention, on a retry that
            // can only fail the same way.
            if (authenticate_pin_interactive(piv, "delete key '" + key_name + "'"))
            {
                // The retry rescans every slot, so its own verdict on what could be read supersedes
                // the first pass's; only the count of slots already cleared carries over.
                const YubiKeyPIV::DeleteByNameResult retry = piv.delete_keys_by_name(key_name);
                result.deleted += retry.deleted;
                result.delete_refused = retry.delete_refused;
                result.unreadable_slot = retry.unreadable_slot;
            }
        }

        deleted += result.deleted;
        undetermined = undetermined || result.delete_refused || result.unreadable_slot;
    }

    if (undetermined)
    {
        mpss::utils::log_and_set_error("Could not clear key '{}' from every attached YubiKey.", key_name);
        return false;
    }

    mpss::utils::log_trace("Cleared {} slot(s) carrying key '{}'.", deleted, key_name);
    return true;
}

bool YubiKeyBackend::verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
                            std::span<const std::byte> sig) const
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_and_set_error("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return false;
    }

    // Check hash length.
    if (!mpss::utils::check_exact_hash_size(hash, algorithm))
    {
        return false;
    }

    const char *group_name = utils::get_group_name(algorithm);
    if (nullptr == group_name)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}' for YubiKey verification.",
                                       get_algorithm_info(algorithm).type_str);
        return false;
    }

    switch (openssl_ecdsa_verify(group_name, hash, public_key, sig))
    {
    case VerifyOutcome::verified:
        return true;
    case VerifyOutcome::mismatch:
        // A plain signature mismatch is a clean negative, not an operational error.
        return false;
    default:
        mpss::utils::log_and_set_error("Signature verification could not be completed.");
        return false;
    }
}

} // namespace mpss::impl::yubikey
