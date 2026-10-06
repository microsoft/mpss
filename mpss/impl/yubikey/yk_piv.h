// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/algorithm.h"
#include "mpss/impl/key_probe.h"
#include "mpss/interaction_handler.h"
#include "mpss/key_policy.h"
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
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
 * - Key generation, signing, public-key extraction, and deletion
 * - Management-key authentication using PIN-protected, explicitly supplied, or explicitly enabled credentials
 */
class YubiKeyPIV
{
  public:
    /**
     * @brief Constructs a YubiKeyPIV object and connects to the YubiKey with the specified serial number.
     *
     * Tries the readers that answered for this serial, verifying the serial after connecting.
     * Stale routes cost at most one scan and retry. An expected key filters routes without PIN
     * authentication. Without it, conflicting name bindings on reachable routes are refused.
     * Cached readers avoid a scan that must wait for all active connections and touches to finish.
     *
     * If connection fails, the object is left in a disconnected state. All subsequent
     * operations will fail gracefully and return error values.
     *
     * @param serial The serial number of the target YubiKey.
     */
    explicit YubiKeyPIV(std::uint32_t serial, std::string_view name = {},
                        std::span<const std::byte> expected_public_key = {}, std::uint8_t slot = 0);

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
     * @brief Get the serial number from the last successful connection, or zero before connecting.
     * @return The serial number.
     */
    [[nodiscard]]
    std::uint32_t get_serial() const noexcept
    {
        return serial_;
    }

    /** @brief Metadata for the current connection; views remain valid until it changes or is destroyed. */
    [[nodiscard]]
    InteractionContext interaction_context() const noexcept
    {
        return {.backend_name = "yubikey", .device_id = device_id_, .key_name = key_name_, .reader_name = reader_name_};
    }

    /**
     * @brief Authenticate with the PIN.
     * @param pin The PIN string.
     * @param retries_out Set to the number of remaining PIN retries on failure, or -1 if unknown.
     * @return The result of the authentication attempt.
     */
    [[nodiscard]]
    mpss::PinResult authenticate_pin(std::string_view pin, int &retries_out);

    /**
     * @brief Authenticate with the management key.
     * Uses the factory-default management key only when explicitly enabled through the environment.
     * @param probe When true, wanting credentials that verifying the PIN may supply is an expected outcome of the
     * call and is reported through the trace log only. Any other failure is still reported.
     * @return true if authentication succeeded, false otherwise.
     */
    [[nodiscard]]
    bool authenticate_mgm_key(bool probe = false);

    /**
     * @brief Outcome of a key generation attempt.
     */
    enum class GenerateResult
    {
        generated,       ///< The key was created in the slot.
        unauthenticated, ///< Refused for want of credentials; verifying the PIN may let a retry through.
        refused          ///< Refused on grounds no credential satisfies; a retry only repeats it.
    };

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
     * @param[out] public_key Optional. On success, the public key the device reports for the key it
     * just generated. This identifies that key: a slot another writer has filled since holds a
     * different one, and nothing else about the slot distinguishes them.
     * @param probe When true, a refusal for want of credentials is an expected outcome of the call and
     * is not reported as an error. Any other failure is still reported.
     * @return GenerateResult::generated on success; GenerateResult::unauthenticated when the device
     * refused for want of credentials, which is the only refusal that verifying a PIN and retrying
     * can change; GenerateResult::refused for every other failure.
     */
    [[nodiscard]]
    GenerateResult generate_key(std::uint8_t slot, std::uint8_t algorithm, KeyPolicy policy = KeyPolicy::none,
                                std::vector<std::byte> *public_key = nullptr, bool probe = false);

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
    [[nodiscard]]
    std::size_t sign(std::uint8_t slot, std::span<const std::byte> hash, Algorithm algorithm, std::span<std::byte> sig);

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
    [[nodiscard]]
    std::size_t get_public_key(std::uint8_t slot, std::span<std::byte> public_key, bool probe = false);

    /**
     * @brief What a slot's metadata says about the key it holds.
     */
    struct SlotMetadata
    {
        std::uint8_t pin_policy{0};
        std::uint8_t touch_policy{0};
        // Where the key came from, which the secure element stamps at generation and a writer
        // cannot supply. A key imported into a slot resides in the same hardware and is protected
        // the same way, yet whoever imported it still holds the private material.
        bool generated_on_device{false};
        std::vector<std::byte> public_key;
    };

    /**
     * @brief Read a slot's key and both of its policies in one exchange with the device.
     *
     * Everything a slot's metadata says arrives together, so asking for one answer costs the same
     * round trip as asking for all three. This is the only way to read a slot's policies.
     *
     * @param slot The PIV slot number.
     * @param[out] metadata Filled when the slot answers. A policy the slot does not state carries
     *                      the firmware default.
     * @param probe When true, a failure is not reported through the last error.
     * @return True when the slot answered and its public key could be read.
     */
    [[nodiscard]]
    bool read_slot_metadata(std::uint8_t slot, SlotMetadata &metadata, bool probe = false);

    /**
     * @brief Outcome of a key deletion attempt.
     */
    enum class DeleteResult
    {
        deleted,         ///< The key is gone from the slot.
        unauthenticated, ///< Refused for want of credentials; verifying the PIN may let a retry through.
        refused          ///< Refused on grounds no credential satisfies; a retry only repeats it.
    };

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
     * @param probe When true, a refusal for want of credentials is an expected outcome of the call and
     * is not reported as an error. Any other failure is still reported.
     * @return DeleteResult::deleted on success; DeleteResult::unauthenticated when the device refused
     * for want of credentials, which is the only refusal that verifying a PIN and retrying can change;
     * DeleteResult::refused for every other failure. The overwrite fallback goes through key
     * generation, so a device that refuses to generate -- a YubiKey FIPS device outside FIPS-approved
     * mode, for instance -- refuses to delete this way too, and for the same unsatisfiable reason.
     */
    [[nodiscard]]
    DeleteResult delete_key(std::uint8_t slot, bool probe = false);

    /**
     * @brief Check if a key exists in the specified slot.
     * @param slot The PIV slot number.
     * @return true if a key exists, and also when occupancy could not be determined, so that a slot
     * which may hold a live key is never offered as free; false only when the device confirms the slot
     * is empty.
     */
    [[nodiscard]]
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
    [[nodiscard]]
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
    [[nodiscard]]
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
     * at the first match and refuses an ambiguous name instead of resolving it arbitrarily. An
     * expected public key restricts matching to slots carrying both that name and that key.
     *
     * @param name The key name to search for.
     * @param expected_public_key Optional public key used to disambiguate slots sharing the name.
     * @return KeyProbeStatus::found with the slot info, KeyProbeStatus::not_found when every slot was read and none
     * matched, or KeyProbeStatus::operational_error when the name could neither be located nor ruled out, or when
     * more than one slot matches the name and optional expected key.
     */
    [[nodiscard]]
    KeyProbeResult<SlotInfo> find_slot_by_name(std::string_view name,
                                               std::span<const std::byte> expected_public_key = {});

    /**
     * @brief Outcome of clearing every slot that carries a name.
     */
    struct DeleteByNameResult
    {
        // How many slots were cleared.
        std::size_t deleted;

        // A slot refused the delete, so the name cannot be reported as cleared.
        bool delete_refused;

        // A slot refused for want of credentials. This is the only refusal that verifying a PIN and
        // retrying can change; every other one stands on grounds no credential satisfies.
        bool needs_authentication;

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
     * @param probe When true, a refusal for want of credentials is an expected outcome of the call and
     * is not reported as an error. Any other failure is still reported.
     * @return How many slots were cleared, and whether any slot refused the delete or could not be
     * read.
     */
    [[nodiscard]]
    DeleteByNameResult delete_keys_by_name(std::string_view name, bool probe = false);

    /**
     * @brief Find a free PIV slot.
     *
     * A slot whose label marks it as available -- a deleted key overwritten on firmware that cannot
     * erase a slot -- is preferred over one that is empty.
     *
     * @return The slot number, or 0 if no free slots are available.
     */
    [[nodiscard]]
    std::uint8_t find_free_slot();

    /**
     * @brief List distinct serials that currently answer on reachable readers.
     *
     * Briefly connects to each smart card reader, reads the serial number, and disconnects. This is
     * a discovery method: it leaves no connection open, and it records which reader answered for
     * each serial, which is what lets a later connection address one reader directly.
     *
     * @return An empty list when no reader answers; nullopt when enumeration itself fails.
     */
    [[nodiscard]]
    static MPSS_DECOR std::optional<std::vector<std::uint32_t>> available_serials();

  private:
    // Held for the life of the connection, so that one device serves one connection at a time and
    // no reader scan runs beside one. The bus is taken first and spans reading which reader answers
    // for the serial as well as connecting to it, so a scan cannot replace that mapping in between. The
    // bus is declared first so that destruction releases the device lock before it, reversing the
    // order they were taken in.
    //
    // A scan wants the bus exclusively, so a thread holding these must not start one: the
    // constructor releases both before rescanning, and opening a second connection or listing
    // devices from a thread that already holds one is refused rather than left to wait.
    std::shared_lock<std::shared_mutex> bus_lock_;
    std::unique_lock<std::mutex> device_lock_;

    ykpiv_state *state_{nullptr};
    // Last successful connection metadata survives disconnect while another route is being tried.
    std::uint32_t serial_{0};
    std::string device_id_;
    std::string key_name_;
    std::string reader_name_;

    // Set when authentication fell back to the publicly known factory-default management key, which
    // is evidence the device still carries factory credentials.
    bool used_default_mgm_key_{false};

    /**
     * @brief Which factory-default credentials the device still appears to carry.
     *
     * Reads the PIV admin data, which records whether the PIN has ever been changed. Only credentials
     * that can be established are named; the management key counts only when authentication actually
     * fell back to the factory default on this connection.
     *
     * @return A sentence to append to a diagnostic, or an empty string when nothing could be
     * established. Absence of evidence is not evidence that the credentials differ from the defaults.
     */
    [[nodiscard]]
    std::string describe_default_credentials();

    [[nodiscard]]
    bool connect_to_reader(const std::string &reader, std::uint32_t target_serial);

    /**
     * @brief Outcome of connecting through the readers cached for a serial.
     */
    enum class ConnectionResult
    {
        connected,         ///< A connection is held; the route that answered is preferred next time.
        unavailable,       ///< No cached route answered, or none satisfied the requested key identity.
        resolution_failed, ///< A route answered but could not resolve the key; the last error says why.
        conflicting_keys   ///< Routes reporting the serial disagree about the key, so none is trusted.
    };
    [[nodiscard]]
    ConnectionResult connect_to_cached_reader(std::uint32_t serial, std::string_view name,
                                              std::span<const std::byte> expected_public_key, std::uint8_t slot);
    [[nodiscard]]
    std::optional<std::vector<std::vector<std::byte>>> keys_by_name(std::string_view name);
    void disconnect();

    /**
     * @brief Read the algorithm of the key held in a slot.
     *
     * @param slot The PIV slot number.
     * @return The algorithm, or Algorithm::unsupported when the metadata could not be read or names an
     * algorithm MPSS does not support. Does not set the last error; the caller reports in its own terms.
     */
    [[nodiscard]]
    Algorithm read_slot_algorithm(std::uint8_t slot);

    /**
     * @brief Whether a slot's certificate label describes the key the slot actually holds.
     *
     * Reading either side can fail, which is not the same as the two disagreeing.
     */
    enum class LabelBinding
    {
        match,       ///< The certificate describes the key the slot holds.
        mismatch,    ///< The certificate describes a different key, or none.
        undetermined ///< Either side could not be read, so the slot may still carry the name.
    };

    /**
     * @brief Whether a label certificate describes the key the slot currently holds.
     *
     * Compares the encoded subject public key of the certificate with the slot's own public key, without
     * decoding either.
     *
     * @param slot The PIV slot number.
     * @param cert The certificate read from that slot.
     * @return LabelBinding::match when the two keys are the same, LabelBinding::mismatch when they
     * differ, and LabelBinding::undetermined when either key could not be read.
     */
    [[nodiscard]]
    LabelBinding slot_key_matches_label(std::uint8_t slot, const X509 *cert);

    /**
     * @brief Outcome of an attempt to erase a slot outright.
     */
    enum class EraseResult
    {
        erased,          ///< The key was destroyed; the slot is left empty.
        unsupported,     ///< The device has no erase command and the slot is unchanged.
        unauthenticated, ///< Refused for want of credentials; verifying the PIN may let a retry through.
        failed           ///< The erase was attempted and failed; the last error is set.
    };

    /**
     * @brief Destroy the key held in a slot and remove the certificate that labeled it.
     *
     * Only firmware new enough to support erasing a PIV slot can do this; on older devices the slot is
     * left untouched and @ref EraseResult::unsupported is returned so the caller can fall back.
     *
     * @param slot The PIV slot number.
     * @param probe When true, a refusal for want of credentials is an expected outcome of the call and
     * is not reported as an error. Any other failure is still reported.
     * @return Whether the slot was erased, cannot be erased on this device, or failed to erase.
     */
    [[nodiscard]]
    EraseResult erase_slot(std::uint8_t slot, bool probe = false);
};

/**
 * @brief Authenticate with PIN via the global interaction handler.
 *
 * Calls @ref mpss::InteractionHandler::request_pin in a loop, passing the result of each attempt back to the
 * handler via @ref mpss::InteractionHandler::notify_pin_result. The handler controls the retry policy by returning
 * std::nullopt to cancel. As a safety net, the function aborts if the handler returns the same PIN that just
 * failed, and also if it returns any PIN this device has already rejected during the lifetime of this loaded
 * copy of MPSS (to prevent lockout from environment-variable-based handlers).
 *
 * @param piv An already-connected @ref YubiKeyPIV instance.
 * @param context Human-readable description of the operation (for the PIN prompt).
 * @return true on success, false on failure or cancellation.
 */
[[nodiscard]]
bool authenticate_pin_interactive(YubiKeyPIV &piv, std::string_view context);

/**
 * @brief Record that a YubiKey rejected a PIN, so that value is never presented to it again.
 *
 * A device allows only a few wrong PINs before it locks, and every operation asks for a PIN afresh, so a
 * configured value that is wrong would otherwise be spent one retry at a time until the device locks. The
 * record is scoped to the serial that rejected the value, because the same PIN may well be correct on a
 * different device, and it lasts for the lifetime of this loaded copy of MPSS.
 *
 * Only a keyed fingerprint is retained, never the PIN: recognizing a value already known to be wrong needs
 * nothing more. The key is drawn from the private DRBG where available, so the stored fingerprints are
 * not a precomputable dictionary over the small space of possible PINs.
 *
 * @param serial The serial number of the YubiKey that rejected the PIN.
 * @param pin The PIN the device rejected. Empty values, and values containing an embedded null, are
 *            ignored because the device is not given them as written.
 */
void remember_rejected_pin(std::uint32_t serial, std::string_view pin);

/**
 * @brief Check whether a YubiKey has already rejected this PIN.
 *
 * @param serial The serial number of the YubiKey about to be asked.
 * @param pin The PIN that would be presented.
 * @return true if this device already rejected this value, in which case presenting it again would only
 *         consume another retry.
 */
[[nodiscard]]
bool pin_already_rejected(std::uint32_t serial, std::string_view pin);

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
