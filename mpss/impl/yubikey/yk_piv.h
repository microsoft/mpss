// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/impl/key_probe.h"
#include "mpss/interaction_handler.h"
#include "mpss/key_policy.h"
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Forward declaration, so this header does not pull in the OpenSSL headers.
using X509 = struct x509_st;

// Forward declare ykpiv_state.
struct ykpiv_state;

namespace mpss::impl::yubikey
{

/**
 * @brief RAII wrapper around libykpiv for managing YubiKey PIV operations.
 *
 * This class handles:
 * - Connecting/disconnecting from the YubiKey
 * - PIN authentication
 * - Key generation, signing, public key extraction, and deletion
 * - Management-key authentication using PIN-protected, explicitly supplied, or explicitly enabled credentials
 */
class YubiKeyPIV
{
  public:
    /**
     * @brief Constructs a YubiKeyPIV object and connects to the YubiKey with the specified serial number.
     *
     * Iterates through available smart card readers and connects to the YubiKey whose serial number matches.
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
     * @param retries_out Set to the number of remaining PIN retries on failure, or -1 if unknown.
     * @return The result of the authentication attempt.
     */
    mpss::PinResult authenticate_pin(std::string_view pin, int &retries_out);

    /**
     * @brief Authenticate with the management key.
     * Uses the factory-default management key only when explicitly enabled through the environment.
     * @return true if authentication succeeded, false otherwise.
     */
    bool authenticate_mgm_key();

    /**
     * @brief Generate a new key pair in the specified slot.
     *
     * The caller must authenticate PIN and/or management key beforehand if required.
     * PIN and touch policies are resolved from the @ref KeyPolicy bitmask, falling back
     * to environment variables and then hardcoded defaults.
     *
     * @param slot The PIV slot number.
     * @param algorithm The YubiKey PIV algorithm constant (YKPIV_ALGO_ECCP256, etc.).
     * @param policy Key policy bitmask. If KeyPolicy::none, uses env vars / defaults.
     * @return true if generation succeeded, false otherwise.
     */
    bool generate_key(std::uint8_t slot, std::uint8_t algorithm, KeyPolicy policy = KeyPolicy::none);

    /**
     * @brief Sign a hash with the key in the specified slot.
     *
     * The caller must authenticate PIN beforehand if the key's PIN policy requires it.
     *
     * @param slot The PIV slot number.
     * @param hash The hash to sign.
     * @param algorithm The MPSS algorithm.
     * @param sig Output buffer for the signature. Must be at least get_max_signature_size() bytes.
     * @param probe When true, an authentication failure is an expected outcome of the call and is not reported as
     * an error. Any other failure is still reported.
     * @return The number of bytes written to sig, or 0 on failure.
     */
    std::size_t sign(std::uint8_t slot, std::span<const std::byte> hash, Algorithm algorithm, std::span<std::byte> sig,
                     bool probe = false);

    /**
     * @brief Extract the public key from the specified slot.
     * @param slot The PIV slot number.
     * @param public_key Output buffer for the public key in ANSI X9.63 format (uncompressed).
     *                   Must be at least get_public_key_size() bytes.
     * @param probe When true, a failure is not reported through the last error. Slot scans read keys
     *              speculatively, and a slot they cannot read is an expected outcome rather than a
     *              failure of the operation the caller asked for.
     * @return The number of bytes written to public_key, or 0 on failure.
     */
    std::size_t get_public_key(std::uint8_t slot, std::span<std::byte> public_key, bool probe = false);

    /**
     * @brief Delete the key in the specified slot.
     *
     * Where the device can erase a slot outright, the key material is destroyed and the slot is left
     * empty. Devices without that command instead have the key overwritten with a throwaway key and
     * the slot marked as available, which is the only way older firmware can render a key unusable.
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
     * Creates a minimal X.509 certificate with the key name embedded in the Subject CN field and writes it to the
     * slot. The subject public key is the public key of the key held in the slot, which is what lets a later read
     * tell a current label from one left behind by a key that has since been replaced. The certificate is signed by
     * an ephemeral key, because the slot key cannot sign without a PIN and, under a touch policy, a user touch; the
     * signature therefore carries no meaning and the certificate is deliberately not self-issued.
     *
     * The caller must authenticate PIN and/or management key beforehand if required.
     *
     * @param slot The PIV slot number.
     * @param name The key name to store.
     * @return true if the label was written successfully, false otherwise.
     */
    bool write_slot_label(std::uint8_t slot, std::string_view name);

    /**
     * @brief Read the key name label from a slot's certificate object.
     *
     * Reads the certificate from the slot and extracts the key name from the Subject CN field. Only reports a name
     * for MPSS-managed certificates (Subject O = "Microsoft", OU = "mpss").
     *
     * @param slot The PIV slot number.
     * @return KeyProbeStatus::found with the key name when the slot holds an MPSS-managed certificate,
     * KeyProbeStatus::not_found when the slot is confirmed to hold no MPSS certificate, and
     * KeyProbeStatus::operational_error when the slot could not be read or its contents could not be interpreted.
     */
    KeyProbeResult<std::string> read_slot_label(std::uint8_t slot);

    /**
     * @brief Find a slot by key name.
     *
     * Scans all usable PIV slots and reads each certificate label, looking for a match.
     *
     * A slot that cannot be read leaves the scan unable to rule the name out, so a scan that finds no match but
     * skipped such a slot reports KeyProbeStatus::operational_error rather than KeyProbeStatus::not_found. A match
     * found in a readable slot is conclusive regardless of any earlier unreadable slot, because only a slot that
     * was read can be returned.
     *
     * Nothing prevents two slots from carrying the same label, so the scan visits every slot rather than stopping
     * at the first match and refuses an ambiguous name instead of resolving it arbitrarily.
     *
     * @param name The key name to search for.
     * @return KeyProbeStatus::found with the slot info, KeyProbeStatus::not_found when every slot was read and none
     * matched, or KeyProbeStatus::operational_error when the name could neither be located nor ruled out, or when
     * more than one slot carries it.
     */
    KeyProbeResult<SlotInfo> find_slot_by_name(std::string_view name);

    /**
     * @brief Outcome of clearing every slot that carries a name.
     */
    struct DeleteByNameResult
    {
        // How many slots were cleared.
        std::size_t deleted;

        // A slot refused the delete. Retrying after authenticating may succeed.
        bool delete_refused;

        // A slot could not be read, so it may still carry the name.
        bool unreadable_slot;
    };

    /**
     * @brief Delete every key whose slot carries this name.
     *
     * Unlike @ref find_slot_by_name, an ambiguous name is not refused: clearing a name is exactly
     * how a name that resolution refuses is recovered. Every matching slot is cleared rather than
     * the first, because leaving one behind would let the name start resolving again to whichever
     * slot survived.
     *
     * @param name The key name to clear.
     * @return How many slots were cleared, and whether any slot refused the delete or could not be
     * read.
     */
    DeleteByNameResult delete_keys_by_name(std::string_view name);

    /**
     * @brief Find the first free (unoccupied) PIV slot.
     * @return The slot number, or 0 if no free slots are available.
     */
    std::uint8_t find_free_slot();

    /**
     * @brief List the serial numbers of all currently available YubiKeys.
     *
     * Briefly connects to each smart card reader, reads the serial number, and disconnects.
     * This is a discovery method - it does not leave any connections open.
     *
     * @return A vector of serial numbers for all reachable YubiKeys.
     */
    // @param device_skipped Optional. Set when a reader answered but the device on it could not be
    // identified, so the returned list is not a complete account of what is attached.
    static MPSS_DECOR std::vector<std::uint32_t> available_serials(bool *device_skipped = nullptr);

  private:
    ykpiv_state *state_{nullptr};
    std::uint32_t serial_{0};

    bool connect(std::uint32_t target_serial);
    void disconnect();

    /**
     * @brief Read the algorithm of the key held in a slot.
     *
     * @param slot The PIV slot number.
     * @return The algorithm, or Algorithm::unsupported when the metadata could not be read or names an
     * algorithm MPSS does not support. Does not set the last error; the caller reports in its own terms.
     */
    Algorithm read_slot_algorithm(std::uint8_t slot);

    /**
     * @brief Whether a label certificate describes the key the slot currently holds.
     *
     * Compares the certificate's subject public key against the slot's own public key.
     *
     * @param slot The PIV slot number.
     * @param cert The certificate read from that slot.
     * @return true when the two keys are the same, false when they differ or the slot key is unreadable.
     */
    // Whether a slot's certificate label describes the key the slot actually holds. Reading either
    // side can fail, which is not the same as the two disagreeing.
    enum class LabelBinding
    {
        match,
        mismatch,
        undetermined
    };

    LabelBinding slot_key_matches_label(std::uint8_t slot, X509 *cert);

    /**
     * @brief Outcome of an attempt to erase a slot outright.
     */
    enum class EraseResult
    {
        erased,      ///< The key was destroyed; the slot is left empty.
        unsupported, ///< The device has no erase command and the slot is unchanged.
        failed       ///< The erase was attempted and failed; the last error is set.
    };

    /**
     * @brief Destroy the key held in a slot and remove the certificate that labeled it.
     *
     * Only firmware new enough to support erasing a PIV slot can do this; on older devices the slot is
     * left untouched and @ref EraseResult::unsupported is returned so the caller can fall back.
     *
     * @param slot The PIV slot number.
     * @return Whether the slot was erased, cannot be erased on this device, or failed to erase.
     */
    EraseResult erase_slot(std::uint8_t slot);
};

/**
 * @brief Authenticate with PIN via the global interaction handler.
 *
 * Calls @ref mpss::InteractionHandler::request_pin in a loop, passing the result of each attempt back to the
 * handler via @ref mpss::InteractionHandler::notify_pin_result. The handler controls the retry policy by returning
 * std::nullopt to cancel. As a safety net, the function aborts if the handler returns the same PIN that just
 * failed (to prevent lockout from environment-variable-based handlers).
 *
 * @param piv An already-connected @ref YubiKeyPIV instance.
 * @param context Human-readable description of the operation (for the PIN prompt).
 * @return true on success, false on failure or cancellation.
 */
[[nodiscard]]
bool authenticate_pin_interactive(YubiKeyPIV &piv, std::string_view context);

/**
 * @brief Check whether a key name is reserved for MPSS internal use.
 *
 * Free and deleted slots are marked by a sentinel label written to the slot's certificate. A user-supplied name
 * equal to that sentinel would collide with the marker, so such names must be rejected before they reach a slot.
 *
 * @param name The key name to check.
 * @return true if the name is reserved and must not be used, false otherwise.
 */
[[nodiscard]]
bool is_reserved_key_name(std::string_view name);

} // namespace mpss::impl::yubikey
