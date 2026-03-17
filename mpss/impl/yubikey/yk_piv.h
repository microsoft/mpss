// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Forward declare ykpiv_state.
struct ykpiv_state;

namespace mpss::impl::yubikey
{

/**
 * @brief Result of a PIN authentication attempt.
 */
enum class PinResult
{
    ok,        /**< PIN verified successfully. */
    wrong_pin, /**< PIN was incorrect (retries may remain). */
    locked,    /**< PIN is locked (too many wrong attempts). Use PUK to unlock. */
    error,     /**< Non-PIN error (e.g., device disconnected). */
};

/**
 * @brief RAII wrapper around libykpiv for managing YubiKey PIV operations.
 *
 * This class handles:
 * - Connecting/disconnecting from the YubiKey
 * - PIN authentication
 * - Key generation, signing, public key extraction, and deletion
 * - All operations use PIN-protected management key mode
 */
class YubiKeyPIV
{
  public:
    /**
     * @brief Constructs a YubiKeyPIV object and connects to a YubiKey.
     *
     * If the MPSS_YUBIKEY_SERIAL environment variable is set, iterates through
     * available smart card readers and connects to the YubiKey whose serial number
     * matches. Otherwise, connects to the first available YubiKey.
     *
     * If connection fails, the object is left in a disconnected state. All subsequent
     * operations will fail gracefully and return error values.
     */
    YubiKeyPIV()
    {
        connect();
    }

    /**
     * @brief Constructs a YubiKeyPIV object and connects to the YubiKey with the specified serial number.
     *
     * Iterates through available smart card readers and connects to the YubiKey whose serial number matches.
     * The MPSS_YUBIKEY_SERIAL environment variable is ignored when an explicit serial is provided.
     *
     * If connection fails, the object is left in a disconnected state. All subsequent
     * operations will fail gracefully and return error values.
     *
     * @param serial The serial number of the target YubiKey.
     */
    explicit YubiKeyPIV(std::uint32_t serial);

    /**
     * @brief Destruct the YubiKeyPIV. Automatically disconnects and performs clean-up.
     */
    ~YubiKeyPIV();

    YubiKeyPIV(const YubiKeyPIV &) = delete;
    YubiKeyPIV &operator=(const YubiKeyPIV &) = delete;
    YubiKeyPIV(YubiKeyPIV &&) = delete;
    YubiKeyPIV &operator=(YubiKeyPIV &&) = delete;

    /**
     * @brief Check if the YubiKey is connected.
     * @return true if connected, false otherwise.
     */
    [[nodiscard]]
    bool is_connected() const noexcept
    {
        return nullptr != state_;
    }

    /**
     * @brief Get the YubiKey serial number.
     * @return The serial number.
     */
    [[nodiscard]]
    std::uint32_t get_serial() const noexcept
    {
        return serial_;
    }

    /**
     * @brief Authenticate with the PIN.
     * @param pin The PIN string.
     * @return The result of the authentication attempt.
     */
    PinResult authenticate_pin(std::string_view pin);

    /**
     * @brief Authenticate with the management key.
     * Uses the default management key if no custom key is set.
     * @return true if authentication succeeded, false otherwise.
     */
    bool authenticate_mgm_key();

    /**
     * @brief Generate a new key pair in the specified slot.
     *
     * The caller must authenticate PIN and/or management key beforehand if required.
     *
     * @param slot The PIV slot number.
     * @param algorithm The YubiKey PIV algorithm constant (YKPIV_ALGO_ECCP256, etc.).
     * @param pin_policy The ykpiv PIN policy constant (YKPIV_PINPOLICY_ONCE, etc.).
     * @param touch_policy The ykpiv touch policy constant (YKPIV_TOUCHPOLICY_NEVER, etc.).
     * @return true if generation succeeded, false otherwise.
     */
    bool generate_key(std::uint8_t slot, std::uint8_t algorithm, std::uint8_t pin_policy, std::uint8_t touch_policy);

    /**
     * @brief Sign a hash with the key in the specified slot.
     *
     * The caller must authenticate PIN beforehand if the key's PIN policy requires it.
     *
     * @param slot The PIV slot number.
     * @param hash The hash to sign.
     * @param algorithm The MPSS algorithm.
     * @param sig Output buffer for the signature. Must be at least get_max_signature_size() bytes.
     * @return The number of bytes written to sig, or 0 on failure.
     */
    std::size_t sign(std::uint8_t slot, std::span<const std::byte> hash, Algorithm algorithm, std::span<std::byte> sig);

    /**
     * @brief Extract the public key from the specified slot.
     * @param slot The PIV slot number.
     * @param public_key Output buffer for the public key in ANSI X9.63 format (uncompressed).
     *                   Must be at least get_public_key_size() bytes.
     * @return The number of bytes written to public_key, or 0 on failure.
     */
    std::size_t get_public_key(std::uint8_t slot, std::span<std::byte> public_key);

    /**
     * @brief Delete the key in the specified slot.
     *
     * The caller must authenticate PIN and/or management key beforehand if required.
     *
     * @param slot The PIV slot number.
     * @return true if deletion succeeded, false otherwise.
     */
    bool delete_key(std::uint8_t slot);

    /**
     * @brief Get the touch policy of the key in the specified slot.
     *
     * Reads the key metadata and returns the touch policy constant. If the
     * metadata cannot be read (e.g., slot is empty), returns YKPIV_TOUCHPOLICY_NEVER
     * as a safe default (no spurious touch notifications).
     *
     * @param slot The PIV slot number.
     * @return The touch policy constant (YKPIV_TOUCHPOLICY_NEVER, YKPIV_TOUCHPOLICY_ALWAYS, etc.).
     */
    std::uint8_t get_key_touch_policy(std::uint8_t slot);

    /**
     * @brief Get the PIN policy of the key in the specified slot.
     *
     * Reads the key metadata and returns the PIN policy constant. If the
     * metadata cannot be read (e.g., slot is empty), returns YKPIV_PINPOLICY_DEFAULT
     * as a safe default (assumes PIN may be needed).
     *
     * @param slot The PIV slot number.
     * @return The PIN policy constant (YKPIV_PINPOLICY_NEVER, YKPIV_PINPOLICY_ONCE, etc.).
     */
    std::uint8_t get_key_pin_policy(std::uint8_t slot);

    /**
     * @brief Check if a key exists in the specified slot.
     * @param slot The PIV slot number.
     * @return true if a key exists, false otherwise.
     */
    bool key_exists(std::uint8_t slot);

    /**
     * @brief Information about a key stored in a PIV slot.
     */
    struct SlotInfo
    {
        std::uint8_t slot{0};
        Algorithm algorithm{Algorithm::unsupported};
        std::uint32_t serial{0};
    };

    /**
     * @brief Write a name label to a slot's certificate object.
     *
     * Creates a minimal self-signed X.509 certificate with the key name embedded in the Subject CN field and writes
     * it to the slot. The caller must authenticate PIN and/or management key beforehand if required.
     *
     * @param slot The PIV slot number.
     * @param name The key name to store.
     * @return true if the label was written successfully, false otherwise.
     */
    bool write_slot_label(std::uint8_t slot, std::string_view name);

    /**
     * @brief Read the key name label from a slot's certificate object.
     *
     * Reads the certificate from the slot and extracts the key name from the Subject CN field. Only returns a name
     * for MPSS-managed certificates (Subject O = "Microsoft", OU = "mpss").
     *
     * @param slot The PIV slot number.
     * @return The key name, or empty string if no MPSS label found.
     */
    std::string read_slot_label(std::uint8_t slot);

    /**
     * @brief Find a slot by key name.
     *
     * Scans all usable PIV slots, reads each certificate label, and returns the slot info for the matching key
     * name.
     *
     * @param name The key name to search for.
     * @return The slot info, or std::nullopt if not found.
     */
    std::optional<SlotInfo> find_slot_by_name(std::string_view name);

    /**
     * @brief Find the first free (unoccupied) PIV slot.
     * @return The slot number, or 0 if no free slots are available.
     */
    std::uint8_t find_free_slot();

    /**
     * @brief List the serial numbers of all currently available YubiKeys.
     *
     * Briefly connects to each smart card reader, reads the serial number, and disconnects.
     * This is a discovery method — it does not leave any connections open.
     *
     * @return A vector of serial numbers for all reachable YubiKeys.
     */
    static std::vector<std::uint32_t> available_serials();

  private:
    ykpiv_state *state_{nullptr};
    std::uint32_t serial_{0};

    bool connect(std::optional<std::uint32_t> target_serial = std::nullopt);
    void disconnect();
};

/**
 * @brief Authenticate with PIN via interactive handler, with retry on failure.
 *
 * Prompts the user for the PIN via the global @ref mpss::InteractionHandler. Retries up to 3 times on
 * authentication failure. To prevent lockout when the PIN comes from the MPSS_YUBIKEY_PIN environment variable
 * (which would provide the same wrong value on every attempt), the function immediately aborts if the handler
 * returns the same PIN that just failed.
 *
 * @param piv An already-connected @ref YubiKeyPIV instance.
 * @param context Human-readable description of the operation (for the PIN prompt).
 * @return true on success, false on failure or cancellation.
 */
[[nodiscard]]
bool authenticate_pin_interactive(YubiKeyPIV &piv, std::string_view context);

} // namespace mpss::impl::yubikey
