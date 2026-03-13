// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_piv.h"
#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/interaction_handler.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <ykpiv/ykpiv.h>

namespace mpss::impl::yubikey
{

// List of usable PIV slots for ECDSA keys (retired slots only). The named slots (9A, 9C, 9D, 9E) won't be used.
constexpr std::array<std::uint8_t, 20> usable_slots = {
    YKPIV_KEY_RETIRED1,  YKPIV_KEY_RETIRED2,  YKPIV_KEY_RETIRED3,  YKPIV_KEY_RETIRED4,  YKPIV_KEY_RETIRED5,
    YKPIV_KEY_RETIRED6,  YKPIV_KEY_RETIRED7,  YKPIV_KEY_RETIRED8,  YKPIV_KEY_RETIRED9,  YKPIV_KEY_RETIRED10,
    YKPIV_KEY_RETIRED11, YKPIV_KEY_RETIRED12, YKPIV_KEY_RETIRED13, YKPIV_KEY_RETIRED14, YKPIV_KEY_RETIRED15,
    YKPIV_KEY_RETIRED16, YKPIV_KEY_RETIRED17, YKPIV_KEY_RETIRED18, YKPIV_KEY_RETIRED19, YKPIV_KEY_RETIRED20};

// Label written to a slot's certificate after the private key has been overwritten
// with a dummy key. Slots bearing this label are treated as free by find_free_slot.
constexpr std::string_view available_slot_label = "(available)";

YubiKeyPIV::YubiKeyPIV()
{
    connect();
}

YubiKeyPIV::YubiKeyPIV(std::uint32_t serial)
{
    connect(serial);
}

YubiKeyPIV::~YubiKeyPIV()
{
    disconnect();
}

bool YubiKeyPIV::connect(std::optional<std::uint32_t> target_serial)
{
    ykpiv_rc rc = ykpiv_init(&state_, 0);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to initialize ykpiv: {}", ykpiv_strerror(rc));
        return false;
    }

    // Fall back to env var if no serial was explicitly provided.
    if (!target_serial)
    {
        target_serial = utils::get_serial_from_env();
    }

    // List available readers and try each one until we find a usable YubiKey.
    char reader_buf[2048] = {};
    std::size_t reader_len = sizeof(reader_buf);
    rc = ykpiv_list_readers(state_, reader_buf, &reader_len);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to list smart card readers: {}", ykpiv_strerror(rc));
        ykpiv_done(state_);
        state_ = nullptr;
        return false;
    }

    // Iterate through readers (multi-string: null-separated, double-null-terminated).
    const char *reader = reader_buf;
    while ('\0' != *reader)
    {
        // Prefix with '@' to force exact reader name matching in ykpiv_connect,
        // which otherwise uses a substring match that can connect to the wrong device.
        const std::string exact_reader = std::string("@") + reader;
        rc = ykpiv_connect(state_, exact_reader.c_str());
        if (YKPIV_OK != rc)
        {
            mpss::utils::log_warning("Reader '{}': connection failed ({}).", reader, ykpiv_strerror(rc));
            reader += std::strlen(reader) + 1;
            continue;
        }

        rc = ykpiv_get_serial(state_, &serial_);
        if (YKPIV_OK != rc)
        {
            mpss::utils::log_warning("Reader '{}': connected but failed to get serial ({}).", reader,
                                     ykpiv_strerror(rc));
            ykpiv_disconnect(state_);
            reader += std::strlen(reader) + 1;
            continue;
        }

        if (target_serial && serial_ != *target_serial)
        {
            mpss::utils::log_debug("Reader '{}': YubiKey serial {} does not match target {}.", reader, serial_,
                                   *target_serial);
            ykpiv_disconnect(state_);
            reader += std::strlen(reader) + 1;
            continue;
        }

        mpss::utils::log_trace("Connected to YubiKey with serial {} on reader '{}'.", serial_, reader);
        return true;
        reader += std::strlen(reader) + 1;
    }

    if (target_serial)
    {
        mpss::utils::log_and_set_error("No YubiKey found with serial number {}.", *target_serial);
    }
    else
    {
        mpss::utils::log_and_set_error("No YubiKey found on any reader.");
    }
    ykpiv_done(state_);
    state_ = nullptr;
    return false;
}

void YubiKeyPIV::disconnect()
{
    if (nullptr != state_)
    {
        ykpiv_disconnect(state_);
        ykpiv_done(state_);
        state_ = nullptr;
    }
}

std::uint32_t YubiKeyPIV::get_serial() const
{
    return serial_;
}

PinResult YubiKeyPIV::authenticate_pin(std::string_view pin)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return PinResult::error;
    }

    // ykpiv_verify requires a null-terminated C string.
    const SecureString pin_str{pin};
    int tries = 0;
    ykpiv_rc rc = ykpiv_verify(state_, pin_str.c_str(), &tries);
    if (YKPIV_OK == rc)
    {
        mpss::utils::log_trace("PIN authentication successful.");
        return PinResult::ok;
    }

    if (YKPIV_PIN_LOCKED == rc || 0 == tries)
    {
        mpss::utils::log_and_set_error(
            "YubiKey PIN is locked. Use the PUK to unlock it or reset the PIV module with 'ykman piv reset'.");
        return PinResult::locked;
    }

    mpss::utils::log_warning("PIN verification failed: {} ({} tries remaining).", ykpiv_strerror(rc), tries);
    return PinResult::wrong_pin;
}

bool YubiKeyPIV::authenticate_mgm_key()
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return false;
    }

    // Try PIN-protected management key first (requires PIN to be verified first).
    ykpiv_mgm protected_mgm = {};
    ykpiv_rc rc = ykpiv_util_get_protected_mgm(state_, &protected_mgm);
    if (YKPIV_OK == rc)
    {
        rc = ykpiv_authenticate2(state_, protected_mgm.data, protected_mgm.len);
        if (YKPIV_OK == rc)
        {
            mpss::utils::log_trace("Authenticated with PIN-protected management key.");
            return true;
        }
        mpss::utils::log_warning("PIN-protected management key authentication failed: {}", ykpiv_strerror(rc));
    }

    // Try management key from environment variable.
    const SecureByteVector env_key = utils::get_mgm_key_from_env();
    if (!env_key.empty())
    {
        rc = ykpiv_authenticate(state_, reinterpret_cast<const unsigned char *>(env_key.data()));
        if (YKPIV_OK == rc)
        {
            mpss::utils::log_trace("Authenticated with management key from MPSS_YUBIKEY_MGM_KEY.");
            return true;
        }
        mpss::utils::log_warning("Management key from MPSS_YUBIKEY_MGM_KEY failed: {}", ykpiv_strerror(rc));
    }

    // Fall back to default YubiKey management key (3DES, 24 bytes).
    const unsigned char default_mgm_key[24] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
                                               0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    rc = ykpiv_authenticate(state_, default_mgm_key);
    if (YKPIV_OK == rc)
    {
        mpss::utils::log_warning(
            "Authenticated with default management key. Consider setting MPSS_YUBIKEY_MGM_KEY or enabling "
            "PIN-protected management key mode.");
        return true;
    }

    mpss::utils::log_warning("Management key authentication failed. PIN-protected management key requires prior PIN "
                             "verification.");
    return false;
}

bool YubiKeyPIV::generate_key(std::uint8_t slot, std::uint8_t algorithm, std::uint8_t pin_policy,
                              std::uint8_t touch_policy)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return false;
    }

    // Output parameters required by ykpiv_util_generate_key.
    // We don't use these values (public key is retrieved separately via metadata),
    // but the API mandates them.
    std::uint8_t *modulus = nullptr;
    std::size_t modulus_len = 0;
    std::uint8_t *exp = nullptr;
    std::size_t exp_len = 0;
    std::uint8_t *point = nullptr;
    std::size_t point_len = 0;

    // Ensure ykpiv-allocated buffers are guaranteed to be freed.
    auto free_ykpiv_buf = [state = state_](std::uint8_t *&ptr) {
        if (nullptr == state)
        {
            mpss::utils::log_warning("YubiKey state is null in free_ykpiv_buf. Potential memory leak.");
            return;
        }
        if (nullptr != ptr)
        {
            ykpiv_rc rc = ykpiv_util_free(state, ptr);
            if (YKPIV_OK != rc)
            {
                mpss::utils::log_warning("Failed to free ykpiv buffer: {}", ykpiv_strerror(rc));
            }
            ptr = nullptr;
        }
    };
    SCOPE_GUARD(free_ykpiv_buf(modulus); free_ykpiv_buf(exp); free_ykpiv_buf(point););

    ykpiv_rc rc = ykpiv_util_generate_key(state_, slot, algorithm, pin_policy, touch_policy, &modulus, &modulus_len,
                                          &exp, &exp_len, &point, &point_len);

    // If authentication error, free first attempt's buffers, authenticate with management key, and retry.
    if (YKPIV_AUTHENTICATION_ERROR == rc)
    {
        free_ykpiv_buf(modulus);
        free_ykpiv_buf(exp);
        free_ykpiv_buf(point);

        if (!authenticate_mgm_key())
        {
            return false;
        }

        rc = ykpiv_util_generate_key(state_, slot, algorithm, pin_policy, touch_policy, &modulus, &modulus_len, &exp,
                                     &exp_len, &point, &point_len);
    }

    // SCOPE_GUARD frees any remaining buffers on return.

    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Key generation failed in slot {}: {}", utils::get_slot_name(slot),
                                       ykpiv_strerror(rc));
        return false;
    }

    return true;
}

std::size_t YubiKeyPIV::sign(std::uint8_t slot, std::span<const std::byte> hash, Algorithm algorithm,
                             std::span<std::byte> sig)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return 0;
    }

    // Convert mpss::Algorithm to YubiKey PIV algorithm constant.
    const std::uint8_t yk_algorithm = utils::mpss_to_yk_algorithm(algorithm);
    if (0 == yk_algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}' for YubiKey signing.",
                                       get_algorithm_info(algorithm).type_str);
        return 0;
    }

    // Sign the hash directly into the caller's buffer.
    std::size_t sig_len = sig.size();

    ykpiv_rc rc = ykpiv_sign_data(state_, reinterpret_cast<const unsigned char *>(hash.data()), hash.size(),
                                  reinterpret_cast<unsigned char *>(sig.data()), &sig_len, yk_algorithm, slot);

    if (YKPIV_OK != rc)
    {
        // Authentication errors are not logged here. The caller is expected to handle them
        // (e.g., by prompting for PIN and retrying).
        if (YKPIV_AUTHENTICATION_ERROR != rc)
        {
            mpss::utils::log_and_set_error("Signing failed in slot {}: {}", utils::get_slot_name(slot),
                                           ykpiv_strerror(rc));
        }
        return 0;
    }

    return sig_len;
}

std::size_t YubiKeyPIV::get_public_key(std::uint8_t slot, std::span<std::byte> public_key)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return 0;
    }

    // Get the public key from metadata.
    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);

    ykpiv_rc rc = ykpiv_get_metadata(state_, slot, metadata_buf, &metadata_len);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to get metadata from slot {}: {}", utils::get_slot_name(slot),
                                       ykpiv_strerror(rc));
        return 0;
    }

    // Parse metadata to extract public key.
    ykpiv_metadata metadata = {};
    rc = ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to parse metadata from slot {}: {}", utils::get_slot_name(slot),
                                       ykpiv_strerror(rc));
        return 0;
    }

    // The public key in metadata is BER-TLV-wrapped with a PIV tag:
    // 86 <length> 04 <X> <Y> (tag 0x86 = public point, context-specific)
    // Parse the TLV to skip the header and get the raw X9.63 uncompressed point.
    const std::uint8_t *pubkey = metadata.pubkey;
    std::size_t pubkey_len = metadata.pubkey_len;
    if (pubkey_len >= 2 && 0x86 == pubkey[0])
    {
        std::size_t header_len = 0;
        if (pubkey[1] < 0x80)
        {
            // Short form: length is a single byte.
            header_len = 2;
        }
        else
        {
            // Long form: first byte is 0x80 | number_of_length_bytes.
            const std::size_t num_len_bytes = pubkey[1] & 0x7F;
            header_len = 2 + num_len_bytes;
        }

        if (header_len > pubkey_len)
        {
            mpss::utils::log_and_set_error("Malformed BER-TLV public key in slot {}: header exceeds data length.",
                                           utils::get_slot_name(slot));
            return 0;
        }

        pubkey += header_len;
        pubkey_len -= header_len;
    }

    if (pubkey_len > public_key.size())
    {
        mpss::utils::log_and_set_error("Public key buffer too small.");
        return 0;
    }

    // Copy directly into the caller's buffer.
    std::copy_n(reinterpret_cast<const std::byte *>(pubkey), pubkey_len, public_key.data());
    return pubkey_len;
}

bool YubiKeyPIV::delete_key(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return false;
    }

    // Overwrite the private key material by generating a dummy key in the slot.
    // Policy is irrelevant for the dummy key - use device defaults.
    if (!generate_key(slot, YKPIV_ALGO_ECCP256, YKPIV_PINPOLICY_DEFAULT, YKPIV_TOUCHPOLICY_DEFAULT))
    {
        return false;
    }

    // Write a marker certificate so the slot is recognized as available for reuse.
    if (!write_slot_label(slot, available_slot_label))
    {
        mpss::utils::log_warning("Private key overwritten but failed to write availability marker for slot {}.",
                                 utils::get_slot_name(slot));

        // The slot is now effectively unusable since the metadata is required to recognize it as free, but the key
        // material has been overwritten so it can't be used maliciously. We log a warning but return success since
        // the key material was securely deleted.
        return true;
    }

    return true;
}

std::uint8_t YubiKeyPIV::get_key_touch_policy(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        return YKPIV_TOUCHPOLICY_NEVER;
    }

    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);

    ykpiv_rc rc = ykpiv_get_metadata(state_, slot, metadata_buf, &metadata_len);
    if (YKPIV_OK != rc)
    {
        return YKPIV_TOUCHPOLICY_NEVER;
    }

    ykpiv_metadata metadata = {};
    rc = ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata);
    if (YKPIV_OK != rc)
    {
        return YKPIV_TOUCHPOLICY_NEVER;
    }

    return metadata.touch_policy;
}

std::uint8_t YubiKeyPIV::get_key_pin_policy(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        return YKPIV_PINPOLICY_DEFAULT;
    }

    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);

    ykpiv_rc rc = ykpiv_get_metadata(state_, slot, metadata_buf, &metadata_len);
    if (YKPIV_OK != rc)
    {
        return YKPIV_PINPOLICY_DEFAULT;
    }

    ykpiv_metadata metadata = {};
    rc = ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata);
    if (YKPIV_OK != rc)
    {
        return YKPIV_PINPOLICY_DEFAULT;
    }

    return metadata.pin_policy;
}

bool YubiKeyPIV::key_exists(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        return false;
    }

    // Try to get metadata from the slot. If it exists, a key is present.
    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);

    ykpiv_rc rc = ykpiv_get_metadata(state_, slot, metadata_buf, &metadata_len);
    return (YKPIV_OK == rc && metadata_len > 0);
}

bool YubiKeyPIV::write_slot_label(std::uint8_t slot, std::string_view name)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return false;
    }

    // Generate an ephemeral EC P-256 key for the certificate.
    // This key is only used to create a syntactically valid self-signed cert;
    // the actual signing key lives in the YubiKey slot.
    EVP_PKEY *ephemeral_key = EVP_EC_gen("P-256"); // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
    if (nullptr == ephemeral_key)
    {
        mpss::utils::log_and_set_error("Failed to generate ephemeral key for slot label.");
        return false;
    }

    // Create a minimal self-signed X.509 certificate.
    X509 *cert = X509_new();
    if (nullptr == cert)
    {
        EVP_PKEY_free(ephemeral_key);
        mpss::utils::log_and_set_error("Failed to create X509 certificate for slot label.");
        return false;
    }

    bool success = false;
    do
    {
        // Version 3 (value 2)
        if (0 == X509_set_version(cert, 2))
        {
            mpss::utils::log_and_set_error("Failed to set X.509 version for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }

        // Serial number = 1
        if (0 == ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
        {
            mpss::utils::log_and_set_error("Failed to set serial number for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }

        // Validity: now to 100 years from now.
        if (nullptr == X509_gmtime_adj(X509_get_notBefore(cert), 0))
        {
            mpss::utils::log_and_set_error("Failed to set notBefore for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }
        if (nullptr == X509_gmtime_adj(X509_get_notAfter(cert), 100L * 365 * 24 * 3600))
        {
            mpss::utils::log_and_set_error("Failed to set notAfter for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }

        // Subject: O=Microsoft, OU=mpss, CN=<key_name>
        X509_NAME *subject = X509_get_subject_name(cert);
        if (0 == X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_UTF8,
                                            reinterpret_cast<const unsigned char *>("Microsoft"), -1, -1, 0))
        {
            mpss::utils::log_and_set_error("Failed to set O field for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }
        if (0 == X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_UTF8,
                                            reinterpret_cast<const unsigned char *>("mpss"), -1, -1, 0))
        {
            mpss::utils::log_and_set_error("Failed to set OU field for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }
        const std::string cn{name};
        if (0 == X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                            reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0))
        {
            mpss::utils::log_and_set_error("Failed to set CN field for slot {} certificate. "
                                           "Name length: {} bytes.",
                                           utils::get_slot_name(slot), cn.size());
            break;
        }

        // Self-signed: issuer = subject.
        if (0 == X509_set_issuer_name(cert, subject))
        {
            mpss::utils::log_and_set_error("Failed to set issuer name for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }

        // Set the ephemeral public key.
        if (0 == X509_set_pubkey(cert, ephemeral_key))
        {
            mpss::utils::log_and_set_error("Failed to set public key for slot {} certificate.",
                                           utils::get_slot_name(slot));
            break;
        }

        // Sign with the ephemeral key.
        if (X509_sign(cert, ephemeral_key, EVP_sha256()) <= 0)
        {
            mpss::utils::log_and_set_error("Failed to sign slot {} certificate.", utils::get_slot_name(slot));
            break;
        }

        // Serialize to DER.
        unsigned char *der = nullptr;
        int der_len = i2d_X509(cert, &der);
        if (der_len <= 0 || nullptr == der)
        {
            mpss::utils::log_and_set_error("Failed to serialize slot {} certificate to DER.",
                                           utils::get_slot_name(slot));
            break;
        }

        // Write certificate to the slot.
        // Try writing directly first (works if management key is already authenticated).
        ykpiv_rc rc =
            ykpiv_util_write_cert(state_, slot, der, static_cast<std::size_t>(der_len), YKPIV_CERTINFO_UNCOMPRESSED);

        if (YKPIV_AUTHENTICATION_ERROR == rc)
        {
            // Failed. Authenticate with management key and retry.
            if (!authenticate_mgm_key())
            {
                OPENSSL_free(der);
                break;
            }
            rc = ykpiv_util_write_cert(state_, slot, der, static_cast<std::size_t>(der_len),
                                       YKPIV_CERTINFO_UNCOMPRESSED);
        }

        OPENSSL_free(der);

        if (YKPIV_OK != rc)
        {
            mpss::utils::log_and_set_error("Failed to write certificate label to slot {}: {}",
                                           utils::get_slot_name(slot), ykpiv_strerror(rc));
            break;
        }

        success = true;
    } while (false);

    X509_free(cert);
    EVP_PKEY_free(ephemeral_key);
    return success;
}

std::string YubiKeyPIV::read_slot_label(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        return {};
    }

    // Read the certificate from the slot.
    std::uint8_t *cert_data = nullptr;
    std::size_t cert_len = 0;
    ykpiv_rc rc = ykpiv_util_read_cert(state_, slot, &cert_data, &cert_len);
    if (YKPIV_OK != rc || nullptr == cert_data || 0 == cert_len)
    {
        return {};
    }

    // Parse the DER-encoded certificate.
    const unsigned char *p = cert_data;
    X509 *cert = d2i_X509(nullptr, &p, static_cast<long>(cert_len));
    ykpiv_util_free(state_, cert_data);

    if (nullptr == cert)
    {
        return {};
    }

    // Extract Subject fields.
    X509_NAME *subject = X509_get_subject_name(cert);
    if (nullptr == subject)
    {
        X509_free(cert);
        return {};
    }

    // Check that O = "Microsoft" and OU = "mpss" (this is our certificate, not someone else's).
    char org_buf[16] = {};
    const int org_len = X509_NAME_get_text_by_NID(subject, NID_organizationName, org_buf, sizeof(org_buf));
    if (org_len <= 0 || std::string_view{org_buf, static_cast<std::size_t>(org_len)} != "Microsoft")
    {
        X509_free(cert);
        return {};
    }

    char ou_buf[8] = {};
    const int ou_len = X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, ou_buf, sizeof(ou_buf));
    if (ou_len <= 0 || std::string_view{ou_buf, static_cast<std::size_t>(ou_len)} != "mpss")
    {
        X509_free(cert);
        return {};
    }

    // Extract CN = key name. Max 64 characters per X.520 ub-common-name, plus null terminator.
    char cn_buf[65] = {};
    const int cn_len = X509_NAME_get_text_by_NID(subject, NID_commonName, cn_buf, sizeof(cn_buf));
    X509_free(cert);

    if (cn_len <= 0)
    {
        return {};
    }

    return std::string{cn_buf, static_cast<std::size_t>(cn_len)};
}

auto YubiKeyPIV::find_slot_by_name(std::string_view name) -> std::optional<SlotInfo>
{
    if (nullptr == state_)
    {
        return std::nullopt;
    }

    for (std::uint8_t slot : usable_slots)
    {
        const std::string label = read_slot_label(slot);
        if (label != name)
        {
            continue;
        }

        // Found the slot. Now get the algorithm from metadata.
        unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
        std::size_t metadata_len = sizeof(metadata_buf);
        ykpiv_rc rc = ykpiv_get_metadata(state_, slot, metadata_buf, &metadata_len);
        if (YKPIV_OK != rc)
        {
            mpss::utils::log_and_set_error("Key '{}' found in slot {} but failed to read metadata: {}", name,
                                           utils::get_slot_name(slot), ykpiv_strerror(rc));
            return std::nullopt;
        }

        ykpiv_metadata metadata = {};
        rc = ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata);
        if (YKPIV_OK != rc)
        {
            mpss::utils::log_and_set_error("Key '{}' found in slot {} but failed to parse metadata: {}", name,
                                           utils::get_slot_name(slot), ykpiv_strerror(rc));
            return std::nullopt;
        }

        const Algorithm algorithm = utils::yk_to_mpss_algorithm(metadata.algorithm);
        if (Algorithm::unsupported == algorithm)
        {
            mpss::utils::log_and_set_error("Key '{}' in slot {} has unsupported algorithm.", name,
                                           utils::get_slot_name(slot));
            return std::nullopt;
        }

        return SlotInfo{.slot = slot, .algorithm = algorithm, .serial = serial_};
    }

    return std::nullopt;
}

std::uint8_t YubiKeyPIV::find_free_slot()
{
    // Prefer reusing slots that were previously deleted (dummy key with availability marker) over consuming a
    // genuinely empty slot.
    for (std::uint8_t slot : usable_slots)
    {
        if (available_slot_label == read_slot_label(slot))
        {
            return slot;
        }
    }

    for (std::uint8_t slot : usable_slots)
    {
        if (!key_exists(slot))
        {
            return slot;
        }
    }

    // No free slots found.
    return 0;
}

bool YubiKeyPIV::has_key_with_name(std::string_view name)
{
    return find_slot_by_name(name).has_value();
}

std::vector<std::uint32_t> YubiKeyPIV::available_serials()
{
    std::vector<std::uint32_t> serials;

    ykpiv_state *state = nullptr;
    ykpiv_rc rc = ykpiv_init(&state, 0);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to initialize ykpiv: {}", ykpiv_strerror(rc));
        return serials;
    }
    SCOPE_GUARD(ykpiv_done(state));

    char reader_buf[2048] = {};
    std::size_t reader_len = sizeof(reader_buf);
    rc = ykpiv_list_readers(state, reader_buf, &reader_len);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to list smart card readers: {}", ykpiv_strerror(rc));
        return serials;
    }

    const char *reader = reader_buf;
    while ('\0' != *reader)
    {
        mpss::utils::log_trace("Trying reader '{}'.", reader);
        const std::string exact_reader = std::string("@") + reader;
        rc = ykpiv_connect(state, exact_reader.c_str());
        if (YKPIV_OK == rc)
        {
            std::uint32_t serial = 0;
            rc = ykpiv_get_serial(state, &serial);
            if (YKPIV_OK == rc && 0 != serial)
            {
                if (std::ranges::find(serials, serial) != serials.end())
                {
                    mpss::utils::log_warning("Duplicate serial {} found on reader '{}'.", serial, reader);
                }
                else
                {
                    mpss::utils::log_trace("Found YubiKey with serial {} on reader '{}'.", serial, reader);
                    serials.push_back(serial);
                }
            }
            else
            {
                mpss::utils::log_trace("Connected to reader '{}' but failed to get serial.", reader);
            }
            ykpiv_disconnect(state);
        }
        else
        {
            mpss::utils::log_trace("Failed to connect to reader '{}'.", reader);
        }
        reader += std::strlen(reader) + 1;
    }

    return serials;
}

bool authenticate_pin_interactive(YubiKeyPIV &piv, std::string_view context)
{
    auto handler = mpss::GetInteractionHandler();
    constexpr int max_attempts = 3;
    mpss::SecureString last_failed_pin;

    for (int attempt = 0; attempt < max_attempts; ++attempt)
    {
        std::optional<mpss::SecureString> pin_opt;
        try
        {
            pin_opt = handler->request_pin(context);
        }
        catch (const std::exception &e)
        {
            mpss::utils::log_and_set_error("Interaction handler error: {}", e.what());
            return false;
        }

        if (!pin_opt || pin_opt->empty())
        {
            mpss::utils::log_and_set_error("YubiKey PIN not provided.");
            return false;
        }

        // If the same PIN was already tried and failed, bail immediately to avoid burning additional retry attempts
        // (especially important when PIN comes from the MPSS_YUBIKEY_PIN environment variable).
        if (!last_failed_pin.empty() && *pin_opt == last_failed_pin)
        {
            mpss::utils::log_and_set_error("Same PIN provided again after failure. Aborting to prevent lockout.");
            return false;
        }

        const PinResult result = piv.authenticate_pin(*pin_opt);
        if (PinResult::ok == result)
        {
            return true;
        }
        if (PinResult::locked == result || PinResult::error == result)
        {
            // PIN is locked or a non-PIN error occurred - retrying won't help.
            return false;
        }

        last_failed_pin = std::move(*pin_opt);
    }

    mpss::utils::log_and_set_error("PIN authentication failed after {} attempts.", max_attempts);
    return false;
}

} // namespace mpss::impl::yubikey
