// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/backend_registry.h"
#include "mpss/implementations/yubikey/yk_keypair.h"
#include "mpss/implementations/yubikey/yk_piv.h"
#include "mpss/implementations/yubikey/yk_utils.h"
#include "mpss/utils/utilities.h"
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>

namespace
{

// Software ECDSA verification using OpenSSL.
bool openssl_ecdsa_verify(const char *group_name, std::span<const std::byte> hash,
                          std::span<const std::byte> public_key, std::span<const std::byte> sig)
{
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
        return false;
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_fromdata_init(build_ctx) <= 0 || EVP_PKEY_fromdata(build_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        EVP_PKEY_CTX_free(build_ctx);
        return false;
    }
    EVP_PKEY_CTX_free(build_ctx);

    // Verify the DER-encoded ECDSA signature against the pre-computed hash.
    EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (nullptr == verify_ctx)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    int result = -1;
    if (EVP_PKEY_verify_init(verify_ctx) > 0)
    {
        result = EVP_PKEY_verify(verify_ctx, reinterpret_cast<const unsigned char *>(sig.data()), sig.size(),
                                 reinterpret_cast<const unsigned char *>(hash.data()), hash.size());
    }

    EVP_PKEY_CTX_free(verify_ctx);
    EVP_PKEY_free(pkey);
    return 1 == result;
}

} // namespace

namespace mpss::impl::yubikey
{

using enum Algorithm;

/**
 * @brief Backend implementation for YubiKey PIV.
 */
class YubiKeyBackend : public Backend
{
  public:
    YubiKeyBackend() = default;
    ~YubiKeyBackend() override = default;

    [[nodiscard]] std::string name() const override
    {
        return "yubikey";
    }

    [[nodiscard]] bool is_algorithm_available(Algorithm algorithm) const override
    {
        return 0 != utils::mpss_to_yk_algorithm(algorithm);
    }

    [[nodiscard]] std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm) const override
    {
        const std::string key_name{name};
        if (key_name.empty())
        {
            mpss::utils::log_warn("Key name cannot be empty.");
            return nullptr;
        }

        if (unsupported == algorithm)
        {
            mpss::utils::log_warn("Unsupported algorithm: {}", get_algorithm_info(algorithm).type_str);
            return nullptr;
        }

        // Check if algorithm is supported by YubiKey.
        const std::uint8_t yk_algorithm = utils::mpss_to_yk_algorithm(algorithm);
        if (0 == yk_algorithm)
        {
            mpss::utils::log_warn("Algorithm not supported by YubiKey PIV.");
            return nullptr;
        }

        // Connect to YubiKey.
        mpss::utils::log_debug("Creating key '{}' with algorithm '{}' on YubiKey.", key_name,
                               get_algorithm_info(algorithm).type_str);
        YubiKeyPIV piv;
        if (!piv.is_connected())
        {
            return nullptr;
        }

        // Check if key already exists on the device.
        if (piv.has_key_with_name(name))
        {
            mpss::utils::log_warn("Key already exists: {}", name);
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
        // without PIN, e.g., via MPSS_YUBIKEY_MGM_KEY or the factory default).
        bool key_generated = piv.generate_key(slot, yk_algorithm);

        if (!key_generated)
        {
            // Generation failed. Most likely it needs PIN for management key access.
            // Prompt for PIN and retry.
            if (!authenticate_pin_interactive(piv, "generate key '" + key_name + "'"))
            {
                return nullptr;
            }

            // PIN is already verified on this connection.
            key_generated = piv.generate_key(slot, yk_algorithm);
            if (!key_generated)
            {
                return nullptr;
            }
        }

        // Write the key name label to the slot's certificate object.
        if (!piv.write_slot_label(slot, name))
        {
            // Clean up: delete the generated key since we can't label it. Deleting a YubiKey PIV key overwrites
            // the key with a dummy key and writes a marker certificate indicating the slot is free. If cleanup
            // itself fails, the slot holds an unlabeled key that MPSS won't find by name, but the slot is
            // consumed until manually cleared.
            if (!piv.delete_key(slot))
            {
                mpss::utils::log_warn("Failed to clean up slot {} after labeling failure.", utils::get_slot_name(slot));
            }
            return nullptr;
        }

        mpss::utils::log_debug("Key '{}' created in YubiKey slot {}.", key_name, utils::get_slot_name(slot));
        return std::make_unique<YubiKeyKeyPair>(name, algorithm, slot);
    }

    [[nodiscard]] std::unique_ptr<KeyPair> open_key(std::string_view name) const override
    {
        const std::string key_name{name};
        if (key_name.empty())
        {
            mpss::utils::log_warn("Key name cannot be empty.");
            return nullptr;
        }

        // Connect to YubiKey.
        mpss::utils::log_debug("Attempting to open key '{}' on YubiKey.", key_name);
        YubiKeyPIV piv;
        if (!piv.is_connected())
        {
            return nullptr;
        }

        // Find the key by name on the device.
        const auto slot_info = piv.find_slot_by_name(name);
        if (!slot_info)
        {
            mpss::utils::log_info("Key not found: {}", key_name);
            return nullptr;
        }

        mpss::utils::log_debug("Key '{}' found in YubiKey slot {} with algorithm '{}'.", key_name,
                               utils::get_slot_name(slot_info->slot),
                               get_algorithm_info(slot_info->algorithm).type_str);
        return std::make_unique<YubiKeyKeyPair>(name, slot_info->algorithm, slot_info->slot);
    }

    [[nodiscard]] bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key,
                              Algorithm algorithm, std::span<const std::byte> sig) const override
    {
        if (hash.empty() || public_key.empty() || sig.empty())
        {
            mpss::utils::log_warn("Hash, public key, and signature cannot be empty.");
            return false;
        }

        if (unsupported == algorithm)
        {
            mpss::utils::log_warn("Unsupported algorithm: {}", get_algorithm_info(algorithm).type_str);
            return false;
        }

        // Check hash length.
        if (!mpss::utils::check_exact_hash_size(hash, algorithm))
        {
            return false;
        }

        const char *group_name = nullptr;
        switch (algorithm)
        {
        case ecdsa_secp256r1_sha256:
            group_name = "P-256";
            break;
        case ecdsa_secp384r1_sha384:
            group_name = "P-384";
            break;
        default:
            mpss::utils::log_and_set_error("Unsupported algorithm for YubiKey verification: {}",
                                           get_algorithm_info(algorithm).type_str);
            return false;
        }

        if (!openssl_ecdsa_verify(group_name, hash, public_key, sig))
        {
            mpss::utils::log_and_set_error("Signature verification failed.");
            return false;
        }
        return true;
    }

    [[nodiscard]] bool is_available() const override
    {
        // Try to connect to a YubiKey.
        YubiKeyPIV piv;
        return piv.is_connected();
    }
};

} // namespace mpss::impl::yubikey

namespace mpss::impl
{

// Explicit registration function for YubiKey backend.
void register_yubikey_backend()
{
    auto backend = std::make_shared<yubikey::YubiKeyBackend>();
    register_backend(backend);
}

} // namespace mpss::impl
