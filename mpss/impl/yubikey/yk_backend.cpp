// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_backend.h"
#include "mpss/impl/yubikey/yk_keypair.h"
#include "mpss/impl/yubikey/yk_piv.h"
#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/utils/host_context.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <cstdint>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

    // Host verification must not inherit application-loaded providers or default properties.
    OSSL_LIB_CTX *libctx = mpss::utils::host_context();
    if (nullptr == libctx)
    {
        return error;
    }

    // Build an EVP_PKEY from the raw uncompressed EC point (X9.63: 04||X||Y).
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char *>(group_name), 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(public_key.data())), public_key.size()),
        OSSL_PARAM_END};

    EVP_PKEY_CTX *build_ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=default");
    if (nullptr == build_ctx)
    {
        return error;
    }

    EVP_PKEY *pkey = nullptr;
    if (0 >= EVP_PKEY_fromdata_init(build_ctx) || 0 >= EVP_PKEY_fromdata(build_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
    {
        EVP_PKEY_CTX_free(build_ctx);
        return error;
    }
    EVP_PKEY_CTX_free(build_ctx);
    SCOPE_GUARD(EVP_PKEY_free(pkey));

    // Verify the DER-encoded ECDSA signature against the pre-computed hash.
    EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=default");
    if (nullptr == verify_ctx)
    {
        return error;
    }
    SCOPE_GUARD(EVP_PKEY_CTX_free(verify_ctx));

    if (0 >= EVP_PKEY_verify_init(verify_ctx))
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

namespace
{

[[nodiscard]]
std::optional<std::uint32_t> select_device(const KeyLocation &location)
{
    // An explicit serial is authoritative; unreachable or invalid targets must not fall back.
    if (location.device_id)
    {
        const std::optional<std::uint32_t> serial = utils::parse_serial(*location.device_id);
        if (!serial)
        {
            mpss::utils::log_and_set_error(
                "Invalid YubiKey device_id: expected a decimal serial number from 1 to 4294967295 "
                "(at most {} characters).",
                utils::max_serial_length);
        }

        return serial;
    }

    // Automatic selection requires exactly one distinct serial in the current reachable snapshot.
    const std::optional<std::vector<std::uint32_t>> serials = YubiKeyPIV::available_serials();
    if (!serials)
    {
        return std::nullopt;
    }

    if (serials->empty())
    {
        mpss::utils::log_and_set_error("No reachable YubiKey found.");
        return std::nullopt;
    }

    if (1 < serials->size())
    {
        mpss::utils::log_and_set_error(
            "Multiple YubiKeys detected. Set device_id to the desired YubiKey serial number.");
        return std::nullopt;
    }

    return serials->front();
}

} // namespace

const char *YubiKeyBackend::name() const
{
    return "yubikey";
}

bool YubiKeyBackend::is_algorithm_available(Algorithm algorithm) const
{
    return 0 != utils::mpss_to_yk_algorithm(algorithm);
}

std::optional<std::vector<std::string>> YubiKeyBackend::available_devices() const
{
    const std::optional<std::vector<std::uint32_t>> serials = YubiKeyPIV::available_serials();
    if (!serials)
    {
        return std::nullopt;
    }

    std::vector<std::string> devices;
    devices.reserve(serials->size());
    for (const std::uint32_t serial : *serials)
    {
        devices.push_back(std::to_string(serial));
    }

    return devices;
}

bool YubiKeyBackend::default_device_id(std::optional<std::string> &device_id) const
{
    device_id.reset();
    std::optional<std::uint32_t> serial;
    if (!utils::get_serial_from_env(serial))
    {
        return false;
    }

    if (serial)
    {
        device_id = std::to_string(*serial);
    }

    return true;
}

std::unique_ptr<KeyPair> YubiKeyBackend::create_key(const KeyLocation &location, Algorithm algorithm,
                                                    KeyPolicy policy) const
{
    const std::string_view name = location.name;
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

    const std::optional<std::uint32_t> selected = select_device(location);
    if (!selected)
    {
        return nullptr;
    }

    // Connect to YubiKey.
    mpss::utils::log_trace("Creating key '{}' with algorithm '{}' on YubiKey.", key_name,
                           get_algorithm_info(algorithm).type_str);
    YubiKeyPIV piv{*selected, name};
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

    const auto find_free_slot = [&piv]() -> std::uint8_t {
        const std::uint8_t free_slot = piv.find_free_slot();
        if (0 == free_slot)
        {
            mpss::utils::log_and_set_error("No free PIV slots available on YubiKey.");
        }
        return free_slot;
    };

    std::uint8_t slot = find_free_slot();
    if (0 == slot)
    {
        return nullptr;
    }

    // Try generating the key without PIN authentication first (succeeds when the management key is available
    // without PIN, e.g., via MPSS_YUBIKEY_MGM_KEY or the explicitly enabled factory default).
    std::vector<std::byte> generated_public_key;
    YubiKeyPIV::GenerateResult generated =
        piv.generate_key(slot, yk_algorithm, policy, &generated_public_key, /* probe */ true);

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

        // The prompt above waits on a person, which is long enough for another writer to take the
        // slot, so one is chosen again now that the PIN is verified on this connection.
        slot = find_free_slot();
        if (0 == slot)
        {
            return nullptr;
        }

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

std::unique_ptr<KeyPair> YubiKeyBackend::open_key(const KeyLocation &location,
                                                  std::span<const std::byte> expected_public_key) const
{
    const std::string_view name = location.name;
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

    const std::optional<std::uint32_t> selected = select_device(location);
    if (!selected)
    {
        return nullptr;
    }

    YubiKeyPIV piv{*selected, name, expected_public_key};
    if (!piv.is_connected())
    {
        return nullptr;
    }

    const KeyProbeResult<YubiKeyPIV::SlotInfo> slot_info = piv.find_slot_by_name(name, expected_public_key);
    if (KeyProbeStatus::found != slot_info.status)
    {
        return nullptr;
    }

    // Read the selected slot again: its contents may have changed since name resolution.
    YubiKeyPIV::SlotMetadata slot_metadata;
    if (!piv.read_slot_metadata(slot_info.value.slot, slot_metadata))
    {
        return nullptr;
    }

    if (!slot_metadata.generated_on_device)
    {
        mpss::utils::log_and_set_error(
            "Refusing to open key '{}': the key in slot {} was imported rather than generated on the device.", key_name,
            utils::get_slot_name(slot_info.value.slot));
        return nullptr;
    }

    if (!expected_public_key.empty() && !std::ranges::equal(slot_metadata.public_key, expected_public_key))
    {
        mpss::utils::log_and_set_error("The opened key does not match the referenced public key.");
        return nullptr;
    }

    return std::make_unique<YubiKeyKeyPair>(name, slot_info.value.algorithm, slot_info.value.slot, piv.get_serial(),
                                            slot_metadata.public_key);
}

bool YubiKeyBackend::delete_key(const KeyLocation &location) const
{
    const std::string_view name = location.name;
    const std::string key_name{name};
    if (is_reserved_key_name(name))
    {
        // "(available)" labels a free slot. Clearing it by name would match every free retired slot
        // on the device and drive a PIN prompt for each.
        mpss::utils::log_and_set_error("Key name '{}' is reserved.", key_name);
        return false;
    }

    const std::optional<std::uint32_t> selected = select_device(location);
    if (!selected)
    {
        return false;
    }

    YubiKeyPIV piv{*selected, name};
    if (!piv.is_connected())
    {
        return false;
    }

    YubiKeyPIV::DeleteByNameResult result = piv.delete_keys_by_name(key_name, /* probe */ true);
    if (result.needs_authentication)
    {
        // Retry only authentication failures; keep the earlier count but use the retry's remaining-failure flags.
        if (authenticate_pin_interactive(piv, "delete key '" + key_name + "'"))
        {
            const YubiKeyPIV::DeleteByNameResult retry = piv.delete_keys_by_name(key_name);
            result.deleted += retry.deleted;
            result.delete_refused = retry.delete_refused;
            result.unreadable_slot = retry.unreadable_slot;
        }
    }

    if (result.delete_refused || result.unreadable_slot)
    {
        mpss::utils::log_and_set_error("Could not clear key '{}' from YubiKey serial {}.", key_name, *selected);
        return false;
    }

    mpss::utils::log_trace("Cleared {} slot(s) carrying key '{}'.", result.deleted, key_name);
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
