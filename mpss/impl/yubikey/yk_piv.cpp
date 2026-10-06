// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/yubikey/yk_piv.h"
#include "mpss/impl/yubikey/yk_utils.h"
#include "mpss/interaction_handler.h"
#include "mpss/utils/host_context.h"
#include "mpss/utils/ossl_ptr.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <ykpiv/ykpiv.h>

namespace
{

// Acquire the bus before a per-serial lock; never scan while holding the bus shared.
// These locks coordinate this library's threads, not access from other processes.
struct DeviceLocks
{
    // Connections hold this shared; discovery holds it exclusively so scans cannot disturb PIV sessions.
    std::shared_mutex bus;

    // Protects reads and writes of both maps, including the cached reader vectors.
    std::mutex registry;

    // Each pointed-to mutex serializes connections to one serial, from PIN authentication through signing.
    // Find/create it under registry, then release registry before acquiring the per-serial lock.
    std::map<std::uint32_t, std::unique_ptr<std::mutex>> by_serial;

    // Cached routes avoid reconnecting to unrelated devices and disturbing their authenticated sessions.
    // Protected by registry; holding the bus shared alone does not make map access safe.
    std::map<std::uint32_t, std::vector<std::string>> readers_by_serial;
};

[[nodiscard]]
DeviceLocks &device_locks()
{
    // Immortal singleton state, for the same reason as the rejected PIN registry: a connection
    // destroyed after this one would otherwise unlock a destroyed mutex. The one-time allocation is
    // reclaimed by the OS at process exit.
    static DeviceLocks &locks = []() -> DeviceLocks & {
        auto *fresh = new DeviceLocks{}; // NOLINT(cppcoreguidelines-owning-memory) - intentional immortal singleton.
        return *fresh;
    }();
    return locks;
}

[[nodiscard]]
std::mutex &device_mutex(std::uint32_t serial)
{
    DeviceLocks &locks = device_locks();
    const std::scoped_lock lock{locks.registry};
    std::unique_ptr<std::mutex> &device = locks.by_serial[serial];
    if (nullptr == device)
    {
        device = std::make_unique<std::mutex>();
    }

    // Entries are never erased, so the returned mutex remains valid after registry is unlocked.
    return *device;
}

// Reject nested connections/scans on this thread: they would reacquire non-recursive locks it holds.
thread_local bool thread_has_connection = false;

// Connects to every reader in turn, records which one answers for each serial, and reports the
// serials found. Connecting to a device disturbs what a session has established on it, so the
// caller must already hold the bus exclusively.
std::optional<std::vector<std::uint32_t>> scan_readers_locked()
{
    ykpiv_state *state = nullptr;
    ykpiv_rc rc = ykpiv_init(&state, 0);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to initialize ykpiv: {}", ykpiv_strerror(rc));
        return std::nullopt;
    }
    SCOPE_GUARD(ykpiv_done(state));

    char reader_buf[2048] = {};
    std::size_t reader_len = sizeof(reader_buf);
    rc = ykpiv_list_readers(state, reader_buf, &reader_len);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to list smart card readers: {}", ykpiv_strerror(rc));
        return std::nullopt;
    }

    std::vector<std::uint32_t> serials;
    std::map<std::uint32_t, std::vector<std::string>> discovered;

    // A double NUL terminated list, so each name follows the one before it.
    for (const char *reader = reader_buf; '\0' != *reader; reader += std::strlen(reader) + 1)
    {
        // Exact rather than substring, since one reader's name can be a prefix of another's.
        const std::string exact_reader = std::string("@") + reader;
        rc = ykpiv_connect(state, exact_reader.c_str());
        if (YKPIV_OK != rc)
        {
            // A connect can take the card handle and still fail afterwards, selecting the PIV
            // applet among the steps that can, which leaves the handle on the state this loop goes
            // on to reuse. The next connect re-establishes the context this releases.
            ykpiv_disconnect(state);

            mpss::utils::log_trace("Reader '{}': connection failed ({}).", reader, ykpiv_strerror(rc));
            continue;
        }

        std::uint32_t serial = 0;
        rc = ykpiv_get_serial(state, &serial);
        ykpiv_disconnect(state);
        if (YKPIV_OK != rc || 0 == serial)
        {
            mpss::utils::log_warning("Reader '{}': connected but failed to get serial ({}).", reader,
                                     ykpiv_strerror(rc));
            continue;
        }

        mpss::utils::log_trace("Found YubiKey with serial {} on reader '{}'.", serial, reader);

        // Different readers can report the same serial; retain each route, but count the serial once.
        std::vector<std::string> &routes = discovered[serial];
        if (routes.empty())
        {
            serials.push_back(serial);
        }

        routes.emplace_back(reader);
    }

    DeviceLocks &locks = device_locks();
    {
        const std::scoped_lock lock{locks.registry};
        // Replace the snapshot: readers seen in earlier scans do not accumulate.
        locks.readers_by_serial = std::move(discovered);
    }

    return serials;
}

// Caller holds the bus shared or exclusively through connection establishment, preventing a rescan.
// Locks registry internally to copy the routes; the caller must not already hold registry.
[[nodiscard]]
std::vector<std::string> cached_readers(std::uint32_t serial)
{
    DeviceLocks &locks = device_locks();
    const std::scoped_lock lock{locks.registry};

    const auto entry = locks.readers_by_serial.find(serial);
    if (locks.readers_by_serial.end() == entry)
    {
        return {};
    }

    return entry->second;
}

void prefer_reader(std::uint32_t serial, const std::string &reader)
{
    DeviceLocks &locks = device_locks();
    const std::scoped_lock lock{locks.registry};

    const auto entry = locks.readers_by_serial.find(serial);
    if (locks.readers_by_serial.end() == entry)
    {
        return;
    }

    std::vector<std::string> &routes = entry->second;
    const auto found = std::ranges::find(routes, reader);
    if (routes.end() != found)
    {
        // Move the successful reader to the front; preserve the order of all other routes.
        std::rotate(routes.begin(), found, found + 1);
    }
}

// Discovers which reader answers for each serial. Takes the bus exclusively, so the caller must
// hold nothing, and reports whether the scan actually happened: a scan that could not run leaves
// what was remembered in place, which must not be mistaken for a fresh answer.
bool rescan_readers()
{
    DeviceLocks &locks = device_locks();
    const std::unique_lock bus{locks.bus};
    return scan_readers_locked().has_value();
}

} // namespace

namespace mpss::impl::yubikey
{

namespace
{
// List of usable PIV slots for keys (retired slots only). The named slots (9A, 9C, 9D, 9E) won't be used.
constexpr std::array<std::uint8_t, 20> usable_slots = {
    YKPIV_KEY_RETIRED1,  YKPIV_KEY_RETIRED2,  YKPIV_KEY_RETIRED3,  YKPIV_KEY_RETIRED4,  YKPIV_KEY_RETIRED5,
    YKPIV_KEY_RETIRED6,  YKPIV_KEY_RETIRED7,  YKPIV_KEY_RETIRED8,  YKPIV_KEY_RETIRED9,  YKPIV_KEY_RETIRED10,
    YKPIV_KEY_RETIRED11, YKPIV_KEY_RETIRED12, YKPIV_KEY_RETIRED13, YKPIV_KEY_RETIRED14, YKPIV_KEY_RETIRED15,
    YKPIV_KEY_RETIRED16, YKPIV_KEY_RETIRED17, YKPIV_KEY_RETIRED18, YKPIV_KEY_RETIRED19, YKPIV_KEY_RETIRED20};

// Label written to a slot's certificate after the private key has been overwritten
// with a dummy key. Slots bearing this label are treated as free by find_free_slot.
constexpr std::string_view available_slot_label = "(available)";

// Destination that turns a key move into a key erasure. Devices that support the command destroy the
// key rather than relocating it; any other destination moves the key to that slot.
constexpr std::uint8_t erase_key_destination = 0xFF;

// Largest X9.63 uncompressed point MPSS handles (P-521: 1 + 66 * 2). YubiKey PIV tops out at P-384,
// but sizing to the library maximum keeps the buffer correct if a larger algorithm is ever reachable.
constexpr std::size_t max_public_key_bytes = 133;

/**
 * @brief Report a failure through the last error, or through the trace log only when speculative.
 *
 * Reading the slots of a device looks at keys it has no reason to expect are there, so a failure is
 * an expected outcome rather than a failure of whatever operation the caller actually asked for.
 */
template <typename... Args> void report_failure(bool probe, std::format_string<Args...> fmt, Args &&...args)
{
    if (probe)
    {
        mpss::utils::log_trace(fmt, std::forward<Args>(args)...);
    }
    else
    {
        mpss::utils::log_and_set_error(fmt, std::forward<Args>(args)...);
    }
}

// Reads and parses a slot's metadata. Every answer metadata carries comes from this one exchange
// with the device, so a caller that wants more than one of them asks once rather than once each.
bool read_parsed_metadata(ykpiv_state *state, std::uint8_t slot, ykpiv_metadata &metadata, bool probe)
{
    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);

    ykpiv_rc rc = ykpiv_get_metadata(state, slot, metadata_buf, &metadata_len);
    if (YKPIV_OK != rc)
    {
        report_failure(probe, "Failed to get metadata from slot {}: {}", utils::get_slot_name(slot),
                       ykpiv_strerror(rc));
        return false;
    }

    rc = ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata);
    if (YKPIV_OK != rc)
    {
        report_failure(probe, "Failed to parse metadata from slot {}: {}", utils::get_slot_name(slot),
                       ykpiv_strerror(rc));
        return false;
    }

    return true;
}

// The public key in metadata is BER-TLV-wrapped with a PIV tag:
// 86 <length> 04 <X> <Y> (tag 0x86 = public point, context-specific)
// Parse the TLV to skip the header and copy out the raw X9.63 uncompressed point.
std::size_t extract_public_point(const ykpiv_metadata &metadata, std::span<std::byte> out, std::uint8_t slot,
                                 bool probe)
{
    const std::uint8_t *pubkey = metadata.pubkey;
    std::size_t pubkey_len = metadata.pubkey_len;
    if (2 <= pubkey_len && 0x86 == pubkey[0])
    {
        std::size_t header_len = 2;
        std::size_t num_len_bytes = 0;
        if (0x80 <= pubkey[1])
        {
            // Long form: the low bits count the bytes the length is spelled in.
            num_len_bytes = pubkey[1] & 0x7FU;
            if (0 == num_len_bytes || num_len_bytes > sizeof(std::size_t))
            {
                report_failure(probe, "Malformed BER-TLV public key in slot {}: unsupported length form.",
                               utils::get_slot_name(slot));
                return 0;
            }
            header_len = 2 + num_len_bytes;
        }

        if (header_len > pubkey_len)
        {
            report_failure(probe, "Malformed BER-TLV public key in slot {}: header exceeds data length.",
                           utils::get_slot_name(slot));
            return 0;
        }

        // Short form spells the length in the byte itself, long form in the bytes that follow it.
        std::size_t declared_len = pubkey[1];
        if (0 != num_len_bytes)
        {
            declared_len = 0;
            for (std::size_t i = 0; i < num_len_bytes; ++i)
            {
                declared_len = (declared_len << 8U) | pubkey[2 + i];
            }
        }

        // A length that disagrees with what is present means the slot is not saying what it appears
        // to say, and the point it holds is not something to guess at.
        if (declared_len != pubkey_len - header_len)
        {
            report_failure(
                probe, "Malformed BER-TLV public key in slot {}: declared length {} does not match the {} bytes given.",
                utils::get_slot_name(slot), declared_len, pubkey_len - header_len);
            return 0;
        }

        pubkey += header_len;
        pubkey_len = declared_len;
    }

    if (pubkey_len > out.size())
    {
        report_failure(probe, "Public key buffer too small.");
        return 0;
    }

    std::copy_n(reinterpret_cast<const std::byte *>(pubkey), pubkey_len, out.data());
    return pubkey_len;
}
} // namespace

bool is_reserved_key_name(std::string_view name)
{
    return available_slot_label == name;
}

YubiKeyPIV::YubiKeyPIV(std::uint32_t serial, std::string_view name, std::span<const std::byte> expected_public_key,
                       std::uint8_t slot)
    : key_name_{name}
{
    if (thread_has_connection)
    {
        mpss::utils::log_and_set_error("Cannot open a YubiKey connection from a thread that already holds one.");
        return;
    }

    bool keep_connection = false;
    SCOPE_GUARD({
        // A constructor that throws has no destructor to close a partially established connection.
        if (!keep_connection)
        {
            disconnect();
        }
    });

    ConnectionResult result = connect_to_cached_reader(serial, name, expected_public_key, slot);
    if (ConnectionResult::connected == result)
    {
        keep_connection = true;
        return;
    }

    // Preserve a useful key-resolution error if rediscovery subsequently loses the device entirely.
    const std::string resolution_error =
        ConnectionResult::resolution_failed == result ? mpss::utils::get_error() : std::string{};
    if (ConnectionResult::conflicting_keys == result || !rescan_readers())
    {
        return;
    }

    result = connect_to_cached_reader(serial, name, expected_public_key, slot);
    if (ConnectionResult::connected == result)
    {
        keep_connection = true;
    }
    else if (ConnectionResult::unavailable == result)
    {
        if (!resolution_error.empty())
        {
            mpss::utils::set_error(resolution_error);
        }
        else if (0 != slot && !expected_public_key.empty())
        {
            mpss::utils::log_and_set_error("Key '{}' is no longer the key this handle opened.", name);
        }
        else
        {
            mpss::utils::log_and_set_error("No reachable YubiKey with serial {} satisfies the requested key identity.",
                                           serial);
        }
    }
}

YubiKeyPIV::ConnectionResult YubiKeyPIV::connect_to_cached_reader(std::uint32_t serial, std::string_view name,
                                                                  std::span<const std::byte> expected_public_key,
                                                                  std::uint8_t slot)
{
    using enum ConnectionResult;

    // Success keeps the connection and locks; every other exit releases this attempt's resources.
    bool keep_connection = false;
    SCOPE_GUARD({
        if (!keep_connection)
        {
            disconnect();
            // Release any owned locks and clear their associations, including on partial acquisition.
            device_lock_ = std::unique_lock<std::mutex>{};
            bus_lock_ = std::shared_lock<std::shared_mutex>{};
        }
    });

    // Keep the route snapshot stable against discovery until this connection attempt finishes.
    bus_lock_ = std::shared_lock{device_locks().bus};

    const std::vector<std::string> readers = cached_readers(serial);
    if (readers.empty())
    {
        return unavailable;
    }

    device_lock_ = std::unique_lock{device_mutex(serial)};

    std::optional<std::vector<std::vector<std::byte>>> observed_keys;
    std::string selected_reader;
    std::string resolution_error;

    for (const auto &reader : readers)
    {
        if (!connect_to_reader(reader, serial))
        {
            continue;
        }

        // An expected public key can identify a usable route even when another route reports different keys.
        if (!expected_public_key.empty())
        {
            std::uint8_t target_slot = slot;
            if (0 == target_slot)
            {
                const KeyProbeResult<SlotInfo> found = find_slot_by_name(name, expected_public_key);
                if (KeyProbeStatus::found == found.status)
                {
                    target_slot = found.value.slot;
                }
                else if (KeyProbeStatus::operational_error == found.status)
                {
                    if (resolution_error.empty())
                    {
                        resolution_error = mpss::utils::get_error();
                    }

                    disconnect();
                    continue;
                }
            }

            SlotMetadata metadata;
            if (0 != target_slot && read_slot_metadata(target_slot, metadata, /* probe */ true) &&
                std::ranges::equal(metadata.public_key, expected_public_key))
            {
                prefer_reader(serial, reader);
                keep_connection = true;
                return connected;
            }

            mpss::utils::log_warning("Reader '{}' does not report the expected public key on serial {}.", reader,
                                     serial);
            disconnect();
            continue;
        }

        if (name.empty() || 1 == readers.size())
        {
            prefer_reader(serial, reader);
            keep_connection = true;
            return connected;
        }

        // Without an expected key, routes claiming the same serial must agree about this name.
        std::optional<std::vector<std::vector<std::byte>>> keys = keys_by_name(name);
        disconnect();
        if (!keys)
        {
            mpss::utils::log_warning("Reader '{}' could not resolve key '{}' on serial {}.", reader, name, serial);
            continue;
        }

        if (observed_keys && *observed_keys != *keys)
        {
            mpss::utils::log_and_set_error("Readers reporting serial {} disagree about key '{}'.", serial, name);
            return conflicting_keys;
        }

        observed_keys = std::move(keys);
        if (selected_reader.empty())
        {
            selected_reader = reader;
        }
    }

    // Probing closed each card session; reconnect and confirm the chosen route still reports the same keys.
    if (observed_keys && connect_to_reader(selected_reader, serial))
    {
        const std::optional<std::vector<std::vector<std::byte>>> confirmed = keys_by_name(name);
        if (confirmed && *confirmed == *observed_keys)
        {
            prefer_reader(serial, selected_reader);
            keep_connection = true;
            return connected;
        }

        mpss::utils::log_and_set_error("The reader's key binding changed while connecting to serial {}.", serial);
        return conflicting_keys;
    }

    if (!resolution_error.empty())
    {
        mpss::utils::set_error(std::move(resolution_error));
        return resolution_failed;
    }

    return unavailable;
}

std::optional<std::vector<std::vector<std::byte>>> YubiKeyPIV::keys_by_name(std::string_view name)
{
    std::vector<std::vector<std::byte>> keys;
    for (const auto slot : usable_slots)
    {
        const KeyProbeResult<std::string> label = read_slot_label(slot);
        if (KeyProbeStatus::operational_error == label.status)
        {
            return std::nullopt;
        }

        if (KeyProbeStatus::found != label.status || label.value != name)
        {
            continue;
        }

        SlotMetadata metadata;
        if (!read_slot_metadata(slot, metadata, /* probe */ true))
        {
            return std::nullopt;
        }

        keys.push_back(std::move(metadata.public_key));
    }

    // Compare the same collection of binary public keys regardless of which slot holds each one.
    std::ranges::sort(keys);
    return keys;
}

YubiKeyPIV::~YubiKeyPIV()
{
    disconnect();
}

bool YubiKeyPIV::connect_to_reader(const std::string &reader, std::uint32_t target_serial)
{
    // Built before the state exists, so that an allocation failure has nothing to strand.
    const std::string exact_reader = std::string("@") + reader;
    std::string connected_reader = reader;
    std::string connected_device = std::to_string(target_serial);

    ykpiv_state *state = nullptr;
    ykpiv_rc rc = ykpiv_init(&state, 0);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to initialize ykpiv: {}", ykpiv_strerror(rc));
        return false;
    }

    rc = ykpiv_connect(state, exact_reader.c_str());
    if (YKPIV_OK != rc)
    {
        ykpiv_done(state);
        mpss::utils::log_trace("Reader '{}': connection failed ({}).", reader, ykpiv_strerror(rc));
        return false;
    }

    std::uint32_t serial = 0;
    rc = ykpiv_get_serial(state, &serial);
    if (YKPIV_OK != rc || serial != target_serial)
    {
        // The cached route is stale: this reader now answers for a different serial.
        ykpiv_disconnect(state);
        ykpiv_done(state);
        mpss::utils::log_debug("Reader '{}' no longer answers for serial {}.", reader, target_serial);
        return false;
    }

    // Ownership moves to the object before anything that can throw runs.
    state_ = state;
    serial_ = serial;
    reader_name_ = std::move(connected_reader);
    device_id_ = std::move(connected_device);
    thread_has_connection = true;

    try
    {
        mpss::utils::log_trace("Connected to YubiKey with serial {} on reader '{}'.", serial, reader);
    }
    catch (...)
    {
        // Throwing out of here leaves the constructor incomplete, so no destructor would run to
        // give back the connection or clear this thread's connection flag.
        disconnect();
        throw;
    }

    return true;
}

void YubiKeyPIV::disconnect()
{
    // Route probing closes card sessions while keeping both locks until the entire attempt ends.
    if (nullptr != state_)
    {
        ykpiv_disconnect(state_);
        ykpiv_done(state_);
        state_ = nullptr;
        thread_has_connection = false;
    }
}

mpss::PinResult YubiKeyPIV::authenticate_pin(std::string_view pin, int &retries_out)
{
    retries_out = -1;

    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return mpss::PinResult::error;
    }

    // ykpiv_verify requires a null-terminated C string.
    const SecureString pin_str{pin};
    int tries = 0;
    ykpiv_rc rc = ykpiv_verify(state_, pin_str.c_str(), &tries);
    if (YKPIV_OK == rc)
    {
        mpss::utils::log_trace("PIN authentication successful.");
        return mpss::PinResult::ok;
    }

    if (YKPIV_PIN_LOCKED == rc || (YKPIV_WRONG_PIN == rc && 0 == tries))
    {
        retries_out = 0;
        mpss::utils::log_and_set_error("YubiKey PIN is locked. Use the PUK to unlock it or reset the PIV module.");
        return mpss::PinResult::locked;
    }

    if (YKPIV_WRONG_PIN != rc)
    {
        // Transport and applet failures leave the retry counter untouched or negative. The device never
        // judged the PIN, so the caller must not record it as rejected.
        mpss::utils::log_and_set_error("PIN verification could not be completed: {}.", ykpiv_strerror(rc));
        return mpss::PinResult::error;
    }

    retries_out = tries;
    mpss::utils::log_warning("PIN verification failed: {} ({} tries remaining).", ykpiv_strerror(rc), tries);
    return mpss::PinResult::wrong_pin;
}

bool YubiKeyPIV::authenticate_mgm_key(bool probe)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return false;
    }

    // Try PIN-protected management key first (requires PIN to be verified first).
    ykpiv_mgm protected_mgm = {};
    SCOPE_GUARD(OPENSSL_cleanse(&protected_mgm, sizeof(protected_mgm)));
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

    // Try management key from environment variable. If MPSS_YUBIKEY_MGM_KEY is set, it must authenticate:
    // a malformed or wrong key is a hard error, never a silent fall-back to the factory-default key.
    if (nullptr != std::getenv("MPSS_YUBIKEY_MGM_KEY"))
    {
        const SecureByteVector env_key = utils::get_mgm_key_from_env();
        if (env_key.empty())
        {
            mpss::utils::log_and_set_error("MPSS_YUBIKEY_MGM_KEY is set but invalid; refusing to fall back to the "
                                           "factory-default management key.");
            return false;
        }
        rc = ykpiv_authenticate2(state_, reinterpret_cast<const unsigned char *>(env_key.data()), env_key.size());
        if (YKPIV_OK == rc)
        {
            mpss::utils::log_trace("Authenticated with management key from MPSS_YUBIKEY_MGM_KEY.");
            return true;
        }
        mpss::utils::log_and_set_error("Management key from MPSS_YUBIKEY_MGM_KEY failed: {}", ykpiv_strerror(rc));
        return false;
    }

    const char *allow_default = std::getenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY");
    if (nullptr == allow_default || !utils::is_affirmative_environment_value(allow_default))
    {
        report_failure(probe,
                       "Management key authentication failed. Refusing to try the publicly known factory-default "
                       "management key unless MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY is set to an affirmative value. "
                       "Configure a PIN-protected management key or set MPSS_YUBIKEY_MGM_KEY.");
        return false;
    }

    // Try the default YubiKey management key (3DES, 24 bytes) only after explicit opt-in.
    const unsigned char default_mgm_key[24] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
                                               0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    rc = ykpiv_authenticate(state_, default_mgm_key);
    if (YKPIV_OK == rc)
    {
        used_default_mgm_key_ = true;
        mpss::utils::log_warning("Authenticated with the publicly known factory-default management key because "
                                 "MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY is enabled. Configure MPSS_YUBIKEY_MGM_KEY or "
                                 "PIN-protected management key mode for normal use.");
        return true;
    }

    // Nothing this connection holds authenticates. The admin data records which mode the management
    // key was configured in, and is readable before the PIN is verified.
    ykpiv_config config = {};
    SCOPE_GUARD(OPENSSL_cleanse(&config, sizeof(config)));
    const bool config_read = (YKPIV_OK == ykpiv_util_get_config(state_, &config));
    if (config_read && YKPIV_CONFIG_MGM_DERIVED == config.mgm_type)
    {
        mpss::utils::log_and_set_error(
            "This YubiKey uses a PIN-derived management key, which is not supported by MPSS.");
        return false;
    }

    if (config_read && YKPIV_CONFIG_MGM_PROTECTED == config.mgm_type)
    {
        report_failure(probe, "Management key authentication failed: the PIN-protected management key is available "
                              "only after the PIN has been verified.");
        return false;
    }

    report_failure(probe, "Management key authentication failed: the factory-default management key was refused and "
                          "MPSS_YUBIKEY_MGM_KEY is not set.");
    return false;
}

YubiKeyPIV::GenerateResult YubiKeyPIV::generate_key(std::uint8_t slot, std::uint8_t algorithm, KeyPolicy policy,
                                                    std::vector<std::byte> *public_key, bool probe)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return GenerateResult::refused;
    }

    // Resolve the PIN and touch policies from the KeyPolicy bitmask, falling back to env vars / defaults.
    const std::uint8_t pin_policy = utils::resolve_pin_policy(policy);
    const std::uint8_t touch_policy = utils::resolve_touch_policy(policy);

    // Output parameters of ykpiv_util_generate_key. Only the point is used, to report the key just
    // generated; the RSA modulus and exponent are mandated by the API.
    std::uint8_t *modulus = nullptr;
    std::size_t modulus_len = 0;
    std::uint8_t *exp = nullptr;
    std::size_t exp_len = 0;
    std::uint8_t *point = nullptr;
    std::size_t point_len = 0;

    // Ensure ykpiv-allocated buffers are guaranteed to be freed.
    auto free_ykpiv_buf = [state = state_](std::uint8_t *&ptr) {
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

        if (!authenticate_mgm_key(probe))
        {
            // The device wants credentials this connection does not have. Verifying the PIN may
            // unlock a PIN-protected management key, so the caller is told a retry is worth trying.
            return GenerateResult::unauthenticated;
        }

        rc = ykpiv_util_generate_key(state_, slot, algorithm, pin_policy, touch_policy, &modulus, &modulus_len, &exp,
                                     &exp_len, &point, &point_len);
    }

    // SCOPE_GUARD frees any remaining buffers on return.

    if (YKPIV_OK == rc)
    {
        if (nullptr != public_key && nullptr != point && 0 != point_len)
        {
            const auto *bytes = reinterpret_cast<const std::byte *>(point);
            public_key->assign(bytes, bytes + point_len);
        }
        return GenerateResult::generated;
    }

    if (YKPIV_CONDITION_ERROR == rc)
    {
        // Not an authentication failure -- that is YKPIV_AUTHENTICATION_ERROR, handled above -- so no
        // credential the caller can supply changes the answer, and retrying only repeats it. The one
        // condition MPSS is known to meet this way is a YubiKey FIPS device whose PIV application is
        // not in FIPS-approved mode: it refuses key generation until the PIN, PUK and management key
        // have all been changed from their factory defaults. ykpiv cannot confirm that reading, since
        // the FIPS flags live in the management applet rather than in PIV, so this states the rule and
        // whatever defaults remain visible instead of claiming to have identified the device.
        mpss::utils::log_and_set_error(
            "Key generation refused in slot {}: {}. A YubiKey FIPS device reports this when its PIV "
            "application is not in FIPS-approved mode, which requires the PIN, PUK and management key to all "
            "differ from their factory defaults.{}",
            utils::get_slot_name(slot), ykpiv_strerror(rc), describe_default_credentials());
        return GenerateResult::refused;
    }

    mpss::utils::log_and_set_error("Key generation failed in slot {}: {}", utils::get_slot_name(slot),
                                   ykpiv_strerror(rc));

    // A wrong PIN is worth another prompt; a locked one is not, and neither is anything else.
    return (YKPIV_AUTHENTICATION_ERROR == rc || YKPIV_WRONG_PIN == rc) ? GenerateResult::unauthenticated
                                                                       : GenerateResult::refused;
}

std::string YubiKeyPIV::describe_default_credentials()
{
    ykpiv_config config = {};
    SCOPE_GUARD(OPENSSL_cleanse(&config, sizeof(config)));
    if (nullptr == state_ || YKPIV_OK != ykpiv_util_get_config(state_, &config))
    {
        return {};
    }

    // Only what the device actually reports. A PIN that has never been changed is recorded in the
    // admin data; the PUK has no equivalent record, so it is never named here even though FIPS-approved
    // mode depends on it too.
    std::string observed;
    if (0 == config.pin_last_changed)
    {
        observed = "the PIN has never been changed from its factory default";
    }
    if (used_default_mgm_key_)
    {
        observed += observed.empty() ? "the factory-default management key authenticated"
                                     : ", and the factory-default management key authenticated";
    }

    if (observed.empty())
    {
        return {};
    }
    return std::format(" On this device {}.", observed);
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
        mpss::utils::log_and_set_error("Signing failed in slot {}: {}", utils::get_slot_name(slot), ykpiv_strerror(rc));
        return 0;
    }

    return sig_len;
}

std::size_t YubiKeyPIV::get_public_key(std::uint8_t slot, std::span<std::byte> public_key, bool probe)
{
    if (nullptr == state_)
    {
        report_failure(probe, "YubiKey not connected.");
        return 0;
    }

    ykpiv_metadata metadata = {};
    if (!read_parsed_metadata(state_, slot, metadata, probe))
    {
        return 0;
    }

    return extract_public_point(metadata, public_key, slot, probe);
}

bool YubiKeyPIV::read_slot_metadata(std::uint8_t slot, SlotMetadata &metadata, bool probe)
{
    if (nullptr == state_)
    {
        report_failure(probe, "YubiKey not connected.");
        return false;
    }

    ykpiv_metadata raw = {};
    if (!read_parsed_metadata(state_, slot, raw, probe))
    {
        return false;
    }

    std::vector<std::byte> point(max_public_key_bytes);
    const std::size_t point_len = extract_public_point(raw, point, slot, probe);
    if (0 == point_len)
    {
        return false;
    }
    point.resize(point_len);

    metadata.pin_policy = raw.pin_policy;
    metadata.touch_policy = raw.touch_policy;
    metadata.generated_on_device = (YKPIV_METADATA_ORIGIN_GENERATED == raw.origin);
    metadata.public_key = std::move(point);
    return true;
}

Algorithm YubiKeyPIV::read_slot_algorithm(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        return Algorithm::unsupported;
    }

    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);
    if (YKPIV_OK != ykpiv_get_metadata(state_, slot, metadata_buf, &metadata_len))
    {
        return Algorithm::unsupported;
    }

    ykpiv_metadata metadata = {};
    if (YKPIV_OK != ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata))
    {
        return Algorithm::unsupported;
    }

    return utils::yk_to_mpss_algorithm(metadata.algorithm);
}

YubiKeyPIV::LabelBinding YubiKeyPIV::slot_key_matches_label(std::uint8_t slot, const X509 *cert)
{
    // Failing to read either side is not the same as the two sides disagreeing. A slot whose key
    // could not be read may still carry the name, so the caller must be able to tell an answer from
    // the absence of one.
    std::array<std::byte, max_public_key_bytes> slot_point{};
    const std::size_t slot_point_len = get_public_key(slot, slot_point, /* probe */ true);
    if (0 == slot_point_len)
    {
        return LabelBinding::undetermined;
    }

    // Compare the encoded keys rather than decoding the label's, which would make the answer depend on
    // what an OpenSSL configuration can decode. Labels carry the key exactly as the slot reports it.
    const unsigned char *label_key = nullptr;
    int label_key_len = 0;
    if (1 != X509_PUBKEY_get0_param(nullptr, &label_key, &label_key_len, nullptr, X509_get_X509_PUBKEY(cert)))
    {
        return LabelBinding::undetermined;
    }

    const bool matches =
        std::cmp_equal(label_key_len, slot_point_len) && 0 == std::memcmp(label_key, slot_point.data(), slot_point_len);
    return matches ? LabelBinding::match : LabelBinding::mismatch;
}

YubiKeyPIV::EraseResult YubiKeyPIV::erase_slot(std::uint8_t slot, bool probe)
{
    ykpiv_rc rc = ykpiv_move_key(state_, slot, erase_key_destination);
    if (YKPIV_AUTHENTICATION_ERROR == rc)
    {
        if (!authenticate_mgm_key(probe))
        {
            // The management key could not be established. A PIN-protected management key is unlocked
            // by verifying the PIN, so the caller is told a retry is worth trying.
            return EraseResult::unauthenticated;
        }

        rc = ykpiv_move_key(state_, slot, erase_key_destination);
    }

    if (YKPIV_NOT_SUPPORTED == rc)
    {
        return EraseResult::unsupported;
    }

    if (YKPIV_AUTHENTICATION_ERROR == rc)
    {
        mpss::utils::log_and_set_error("Failed to erase the key in slot {}: {}", utils::get_slot_name(slot),
                                       ykpiv_strerror(rc));
        return EraseResult::unauthenticated;
    }

    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to erase the key in slot {}: {}", utils::get_slot_name(slot),
                                       ykpiv_strerror(rc));
        return EraseResult::failed;
    }

    // Discard the label describing the key that was just destroyed. The key is removed first so that a
    // failure here cannot strand the slot: without a key the slot reads as free and is reclaimed, and a
    // label left behind cannot resolve a name because it no longer matches the key in the slot.
    rc = ykpiv_util_delete_cert(state_, slot);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_warning("Erased the key in slot {} but could not remove its label: {}",
                                 utils::get_slot_name(slot), ykpiv_strerror(rc));
    }

    return EraseResult::erased;
}

YubiKeyPIV::DeleteResult YubiKeyPIV::delete_key(std::uint8_t slot, bool probe)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return DeleteResult::refused;
    }

    using enum EraseResult;
    switch (erase_slot(slot, probe))
    {
    case erased:
        return DeleteResult::deleted;
    case unauthenticated:
        return DeleteResult::unauthenticated;
    case failed:
        return DeleteResult::refused;
    case unsupported:
        break;
    }

    // The device cannot erase a slot, so render the key unusable by overwriting it instead. Policy is
    // irrelevant for the dummy key; KeyPolicy::none resolves through the MPSS_YUBIKEY_*POLICY
    // environment to the MPSS defaults.
    const GenerateResult overwritten = generate_key(slot, YKPIV_ALGO_ECCP256, KeyPolicy::none, nullptr, probe);
    if (GenerateResult::generated != overwritten)
    {
        // Deleting this way is a generation, so it inherits generation's refusals verbatim -- including
        // a device that will not generate at all, which no credential the caller supplies can change.
        return (GenerateResult::unauthenticated == overwritten) ? DeleteResult::unauthenticated : DeleteResult::refused;
    }

    // Write a marker certificate so the slot is recognized as available for reuse.
    if (!write_slot_label(slot, available_slot_label))
    {
        mpss::utils::log_warning("Private key overwritten but failed to write availability marker for slot {}.",
                                 utils::get_slot_name(slot));

        // The slot is now effectively unusable since the metadata is required to recognize it as free, but the key
        // that was there has been overwritten and cannot be used through the slot any more. We log a warning but
        // return success on that basis; overwriting is not evidence of physical erasure.
        return DeleteResult::deleted;
    }

    return DeleteResult::deleted;
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
    if (YKPIV_OK == rc)
    {
        return 0 < metadata_len;
    }
    if (YKPIV_KEY_ERROR == rc || YKPIV_INVALID_OBJECT == rc)
    {
        // Slot is confirmed empty: the card reports no object in this slot. Which of the two
        // "not found" codes the firmware returns for an empty slot varies by firmware.
        return false;
    }

    // Occupancy could not be determined (e.g. transient transport error). Treat as occupied so
    // find_free_slot does not select the slot and overwrite a live key.
    mpss::utils::log_warning("Could not determine occupancy of slot {}: {}. Treating as occupied.",
                             utils::get_slot_name(slot), ykpiv_strerror(rc));
    return true;
}

bool YubiKeyPIV::write_slot_label(std::uint8_t slot, std::string_view name)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        return false;
    }

    // The certificate names the slot's own key as its subject, so a label can be checked against the
    // key it claims to describe. Read that key first: a label written against anything else would
    // assert a name for a key that is not there.
    std::array<std::byte, max_public_key_bytes> slot_point_buf{};
    const std::size_t slot_point_len = get_public_key(slot, slot_point_buf);
    if (0 == slot_point_len)
    {
        return false;
    }

    const Algorithm slot_algorithm = read_slot_algorithm(slot);
    const int group_nid = utils::get_group_nid(slot_algorithm);
    if (NID_undef == group_nid)
    {
        mpss::utils::log_and_set_error("Cannot label slot {}: its key uses an unsupported algorithm.",
                                       utils::get_slot_name(slot));
        return false;
    }

    OSSL_LIB_CTX *host = mpss::utils::host_context();
    if (nullptr == host)
    {
        mpss::utils::log_and_set_error("Failed to initialize OpenSSL for the label of slot {}.",
                                       utils::get_slot_name(slot));
        return false;
    }

    // The slot's private key cannot sign here without a PIN and, under a touch policy, a user touch,
    // so the certificate is signed by an ephemeral key. The signature therefore proves nothing; the
    // binding that matters is the subject public key set below. X.509 mandates a signature and hence a
    // digest, so one is produced to satisfy the format and no property of that hash is relied upon.
    EVP_PKEY *ephemeral_key = EVP_PKEY_Q_keygen(host, "provider=default", "EC", const_cast<char *>("P-384"));
    if (nullptr == ephemeral_key)
    {
        mpss::utils::log_and_set_error("Failed to generate ephemeral key for slot label.");
        return false;
    }
    SCOPE_GUARD(EVP_PKEY_free(ephemeral_key));

    // Create a minimal X.509 certificate to carry the label. X509_sign fetches in the certificate's context.
    X509 *cert = X509_new_ex(host, "provider=default");
    if (nullptr == cert)
    {
        mpss::utils::log_and_set_error("Failed to create X509 certificate for slot label.");
        return false;
    }
    SCOPE_GUARD(X509_free(cert));

    // Version 3 (value 2)
    if (0 == X509_set_version(cert, 2))
    {
        mpss::utils::log_and_set_error("Failed to set X.509 version for slot {} certificate.",
                                       utils::get_slot_name(slot));
        return false;
    }

    // Serial number = 1
    if (0 == ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
    {
        mpss::utils::log_and_set_error("Failed to set serial number for slot {} certificate.",
                                       utils::get_slot_name(slot));
        return false;
    }

    // Validity: now to 100 years from now.
    if (nullptr == X509_gmtime_adj(X509_get_notBefore(cert), 0))
    {
        mpss::utils::log_and_set_error("Failed to set notBefore for slot {} certificate.", utils::get_slot_name(slot));
        return false;
    }
    if (nullptr == X509_time_adj_ex(X509_get_notAfter(cert), 100 * 365, 0, nullptr))
    {
        mpss::utils::log_and_set_error("Failed to set notAfter for slot {} certificate.", utils::get_slot_name(slot));
        return false;
    }

    // Subject: O=Microsoft, OU=mpss, CN=<key_name>
    X509_NAME *subject = X509_get_subject_name(cert);
    if (0 == X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_UTF8,
                                        reinterpret_cast<const unsigned char *>("Microsoft"), -1, -1, 0))
    {
        mpss::utils::log_and_set_error("Failed to set O field for slot {} certificate.", utils::get_slot_name(slot));
        return false;
    }
    if (0 == X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_UTF8, reinterpret_cast<const unsigned char *>("mpss"),
                                        -1, -1, 0))
    {
        mpss::utils::log_and_set_error("Failed to set OU field for slot {} certificate.", utils::get_slot_name(slot));
        return false;
    }
    const std::string cn{name};
    if (0 == X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                        reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0))
    {
        mpss::utils::log_and_set_error("Failed to set CN field for slot {} certificate. "
                                       "Name length: {} bytes.",
                                       utils::get_slot_name(slot), cn.size());
        return false;
    }

    // The certificate is signed by a key that is not its subject, so naming the subject as issuer
    // would assert a self-signature that does not verify. The issuer omits the OU the subject always
    // carries, so the two names cannot coincide whatever the key is called.
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (0 == X509_NAME_add_entry_by_txt(issuer, "O", MBSTRING_UTF8,
                                        reinterpret_cast<const unsigned char *>("Microsoft"), -1, -1, 0) ||
        0 == X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_UTF8,
                                        reinterpret_cast<const unsigned char *>("mpss slot label (not an issuer)"), -1,
                                        -1, 0))
    {
        mpss::utils::log_and_set_error("Failed to set issuer name for slot {} certificate.",
                                       utils::get_slot_name(slot));
        return false;
    }

    // Bind the label to the slot's key: the subject public key is the key this name describes. Set the
    // fields directly: setting an EVP_PKEY would decode it in the application's default context.
    // OBJ_nid2obj returns static objects, which the structure holds without owning them.
    mpss::utils::openssl_buf_ptr<unsigned char> point(
        static_cast<unsigned char *>(OPENSSL_memdup(slot_point_buf.data(), slot_point_len)));
    if (!point ||
        1 != X509_PUBKEY_set0_param(X509_get_X509_PUBKEY(cert), OBJ_nid2obj(NID_X9_62_id_ecPublicKey), V_ASN1_OBJECT,
                                    OBJ_nid2obj(group_nid), point.get(), static_cast<int>(slot_point_len)))
    {
        mpss::utils::log_and_set_error("Failed to set public key for slot {} certificate.", utils::get_slot_name(slot));
        return false;
    }
    static_cast<void>(point.release());

    // Sign with the ephemeral key.
    if (0 >= X509_sign(cert, ephemeral_key, EVP_sha384()))
    {
        mpss::utils::log_and_set_error("Failed to sign slot {} certificate.", utils::get_slot_name(slot));
        return false;
    }

    // Serialize to DER.
    unsigned char *der = nullptr;
    int der_len = i2d_X509(cert, &der);
    if (0 >= der_len || nullptr == der)
    {
        mpss::utils::log_and_set_error("Failed to serialize slot {} certificate to DER.", utils::get_slot_name(slot));
        return false;
    }
    SCOPE_GUARD(OPENSSL_free(der));

    // Write certificate to the slot.
    // Try writing directly first (works if management key is already authenticated).
    ykpiv_rc rc =
        ykpiv_util_write_cert(state_, slot, der, static_cast<std::size_t>(der_len), YKPIV_CERTINFO_UNCOMPRESSED);

    if (YKPIV_AUTHENTICATION_ERROR == rc)
    {
        // Failed. Authenticate with management key and retry.
        if (!authenticate_mgm_key())
        {
            return false;
        }
        rc = ykpiv_util_write_cert(state_, slot, der, static_cast<std::size_t>(der_len), YKPIV_CERTINFO_UNCOMPRESSED);
    }

    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Failed to write certificate label to slot {}: {}", utils::get_slot_name(slot),
                                       ykpiv_strerror(rc));
        return false;
    }

    return true;
}

namespace
{
/**
 * @brief Disambiguate a @c YKPIV_INVALID_OBJECT result from @c ykpiv_util_read_cert.
 *
 * That code is reported both for a slot that holds nothing and for one holding an object it could not
 * decode. Those mean opposite things to a probe that runs before key creation, so this re-fetches the
 * raw PIV object to separate them: a not-found status word from the card confirms the slot is empty,
 * while a successful fetch proves the slot holds data, which may be a key stored under the name being
 * probed. Only meaningful once @c ykpiv_util_read_cert has already failed with that code - a
 * successful fetch is read as "present but undecodable", which a valid certificate would not be.
 *
 * @c key_exists reads the same code from @c ykpiv_get_metadata, where it is unambiguous, and is
 * correct to treat it as an empty slot.
 *
 * @param state Connected ykpiv session.
 * @param slot The slot to probe.
 * @return not_found if the slot is confirmed to hold no certificate object; operational_error if it
 * holds one that could not be decoded, or if occupancy could not be established at all.
 */
KeyProbeStatus probe_certificate_object(ykpiv_state *state, std::uint8_t slot)
{
    const int object_id = static_cast<int>(ykpiv_util_slot_object(slot));
    if (-1 == object_id)
    {
        // The slot maps to no PIV data object, so there is nothing that could hold a certificate.
        return KeyProbeStatus::not_found;
    }

    unsigned char object_buf[YKPIV_OBJ_MAX_SIZE];
    unsigned long object_len = sizeof(object_buf);
    const ykpiv_rc rc = ykpiv_fetch_object(state, object_id, object_buf, &object_len);
    if (YKPIV_KEY_ERROR == rc || YKPIV_INVALID_OBJECT == rc)
    {
        // Here these codes come only from a status word, so the card is reporting no such object.
        return KeyProbeStatus::not_found;
    }

    // YKPIV_OK proves an object is present that ykpiv_util_read_cert could not decode; any other
    // failure leaves occupancy unknown. Neither rules out a key stored under the requested name.
    return KeyProbeStatus::operational_error;
}
} // namespace

KeyProbeResult<std::string> YubiKeyPIV::read_slot_label(std::uint8_t slot)
{
    if (nullptr == state_)
    {
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    // Read the certificate from the slot.
    std::uint8_t *cert_data = nullptr;
    std::size_t cert_len = 0;
    ykpiv_rc rc = ykpiv_util_read_cert(state_, slot, &cert_data, &cert_len);
    if (YKPIV_KEY_ERROR == rc)
    {
        // On this path the code can only originate from the SW_ERR_REFERENCE_NOT_FOUND or
        // SW_ERR_INCORRECT_SLOT status word, so the slot is confirmed to hold no certificate.
        return {.status = KeyProbeStatus::not_found, .value = {}};
    }
    if (YKPIV_INVALID_OBJECT == rc)
    {
        // Ambiguous: an empty slot and an undecodable certificate share this code. See
        // probe_certificate_object above.
        const KeyProbeStatus object_status = probe_certificate_object(state_, slot);
        if (KeyProbeStatus::operational_error == object_status)
        {
            mpss::utils::log_warning("Slot {} holds a certificate that could not be decoded.",
                                     utils::get_slot_name(slot));
        }
        return {.status = object_status, .value = {}};
    }
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_warning("Could not read the certificate in slot {}: {}.", utils::get_slot_name(slot),
                                 ykpiv_strerror(rc));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }
    if (nullptr == cert_data || 0 == cert_len)
    {
        return {.status = KeyProbeStatus::not_found, .value = {}};
    }
    SCOPE_GUARD(ykpiv_util_free(state_, cert_data));

    // Parse in MPSS's own context: parsing decodes the embedded key, and the default context belongs to the
    // application.
    OSSL_LIB_CTX *host = mpss::utils::host_context();
    if (nullptr == host)
    {
        mpss::utils::log_warning("Could not initialize OpenSSL to read the certificate in slot {}.",
                                 utils::get_slot_name(slot));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    const unsigned char *p = cert_data;
    X509 *cert = reinterpret_cast<X509 *>(
        ASN1_item_d2i_ex(nullptr, &p, static_cast<long>(cert_len), ASN1_ITEM_rptr(X509), host, "provider=default"));
    if (nullptr == cert)
    {
        mpss::utils::log_warning("Could not parse the certificate in slot {}.", utils::get_slot_name(slot));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }
    SCOPE_GUARD(X509_free(cert));

    X509_NAME *subject = X509_get_subject_name(cert);
    if (nullptr == subject)
    {
        mpss::utils::log_warning("The certificate in slot {} has no subject name.", utils::get_slot_name(slot));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    // Check that O = "Microsoft" and OU = "mpss" (this is our certificate, not someone else's).
    char org_buf[16] = {};
    const int org_len = X509_NAME_get_text_by_NID(subject, NID_organizationName, org_buf, sizeof(org_buf));
    if (0 >= org_len || "Microsoft" != std::string_view{org_buf, static_cast<std::size_t>(org_len)})
    {
        return {.status = KeyProbeStatus::not_found, .value = {}};
    }

    char ou_buf[8] = {};
    const int ou_len = X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, ou_buf, sizeof(ou_buf));
    if (0 >= ou_len || "mpss" != std::string_view{ou_buf, static_cast<std::size_t>(ou_len)})
    {
        return {.status = KeyProbeStatus::not_found, .value = {}};
    }

    // Extract CN = key name. Max 64 characters per X.520 ub-common-name, plus null terminator.
    char cn_buf[65] = {};
    const int cn_len = X509_NAME_get_text_by_NID(subject, NID_commonName, cn_buf, sizeof(cn_buf));
    if (0 >= cn_len)
    {
        mpss::utils::log_warning("The MPSS certificate in slot {} has no common name.", utils::get_slot_name(slot));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    // The label names a key, so it counts only while it still describes the key that is there. A
    // certificate left behind by a key that has since been replaced names something the slot no
    // longer holds, and reporting that name would hand a caller a key it did not ask for.
    const LabelBinding binding = slot_key_matches_label(slot, cert);
    if (LabelBinding::undetermined == binding)
    {
        mpss::utils::log_warning("Could not tell whether the label in slot {} describes the key held there.",
                                 utils::get_slot_name(slot));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }
    if (LabelBinding::mismatch == binding)
    {
        mpss::utils::log_warning("Ignoring the label in slot {}: it does not describe the key held there.",
                                 utils::get_slot_name(slot));
        return {.status = KeyProbeStatus::not_found, .value = {}};
    }

    return {.status = KeyProbeStatus::found, .value = std::string{cn_buf, static_cast<std::size_t>(cn_len)}};
}

YubiKeyPIV::DeleteByNameResult YubiKeyPIV::delete_keys_by_name(std::string_view name, bool probe)
{
    DeleteByNameResult result{};
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("YubiKey not connected.");
        result.unreadable_slot = true;
        return result;
    }

    // Every slot carrying the name is cleared, not just the first. Leaving one behind would let a
    // name that resolution refused as ambiguous start resolving again, to whichever slot survived.
    for (std::uint8_t slot : usable_slots)
    {
        const KeyProbeResult<std::string> label = read_slot_label(slot);
        if (KeyProbeStatus::operational_error == label.status)
        {
            // The slot may carry the name, so the name cannot be reported as cleared.
            mpss::utils::log_warning("Slot {} could not be read while clearing key '{}'.", utils::get_slot_name(slot),
                                     name);
            result.unreadable_slot = true;
            continue;
        }
        if (KeyProbeStatus::not_found == label.status || label.value != name)
        {
            continue;
        }

        const DeleteResult cleared = delete_key(slot, probe);
        if (DeleteResult::deleted == cleared)
        {
            ++result.deleted;
            continue;
        }

        result.delete_refused = true;
        if (DeleteResult::unauthenticated == cleared)
        {
            result.needs_authentication = true;
        }
    }

    return result;
}

KeyProbeResult<YubiKeyPIV::SlotInfo> YubiKeyPIV::find_slot_by_name(std::string_view name,
                                                                   std::span<const std::byte> expected_public_key)
{
    if (nullptr == state_)
    {
        mpss::utils::log_and_set_error("Not connected to a YubiKey.");
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    // Set for any slot that could not be read; consumed after the scan.
    bool undetermined = false;

    // Nothing prevents two slots from carrying the same label. MPSS refuses to create a duplicate,
    // but another PIV application can write one, as can a create that was interrupted between
    // generating the key and labeling its slot. Scan every slot rather than stopping at the first
    // match, so that an ambiguous name is refused instead of silently resolving to whichever slot
    // happens to be scanned first.
    std::uint8_t match_slot = 0;
    std::size_t match_count = 0;
    std::string match_slot_names;

    for (std::uint8_t slot : usable_slots)
    {
        const KeyProbeResult<std::string> label = read_slot_label(slot);
        if (KeyProbeStatus::operational_error == label.status)
        {
            undetermined = true;
            continue;
        }
        if (KeyProbeStatus::not_found == label.status || label.value != name)
        {
            continue;
        }
        if (!expected_public_key.empty())
        {
            SlotMetadata metadata;
            if (!read_slot_metadata(slot, metadata, /* probe */ true))
            {
                undetermined = true;
                continue;
            }
            if (!std::ranges::equal(metadata.public_key, expected_public_key))
            {
                continue;
            }
        }

        if (0 != match_count)
        {
            match_slot_names += ", ";
        }
        match_slot_names += utils::get_slot_name(slot);
        match_slot = slot;
        ++match_count;
    }

    if (1 < match_count)
    {
        if (expected_public_key.empty())
        {
            mpss::utils::log_and_set_error("Refusing to resolve key '{}': {} slots share this name ({}).", name,
                                           match_count, match_slot_names);
        }
        else
        {
            mpss::utils::log_and_set_error(
                "Refusing to resolve key '{}': {} slots share this name and expected public key ({}).", name,
                match_count, match_slot_names);
        }
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    // An unreadable slot could hold the requested name, so a scan that found nothing cannot assert the
    // name is absent. A scan that found a match can still return it: only a slot that was read can be
    // returned, so a second copy hidden in an unreadable slot is unreachable either way.
    if (undetermined)
    {
        if (0 == match_count)
        {
            mpss::utils::log_and_set_error("Could not determine whether key '{}' is present: at least one slot "
                                           "could not be read.",
                                           name);
            return {.status = KeyProbeStatus::operational_error, .value = {}};
        }
        mpss::utils::log_warning("At least one slot could not be read while resolving key '{}'.", name);
    }

    if (0 == match_count)
    {
        return {.status = KeyProbeStatus::not_found, .value = {}};
    }

    // Exactly one slot matches. Now get the algorithm from metadata.
    unsigned char metadata_buf[YKPIV_OBJ_MAX_SIZE];
    std::size_t metadata_len = sizeof(metadata_buf);
    ykpiv_rc rc = ykpiv_get_metadata(state_, match_slot, metadata_buf, &metadata_len);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Key '{}' found in slot {} but failed to read metadata: {}", name,
                                       utils::get_slot_name(match_slot), ykpiv_strerror(rc));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    ykpiv_metadata metadata = {};
    rc = ykpiv_util_parse_metadata(metadata_buf, metadata_len, &metadata);
    if (YKPIV_OK != rc)
    {
        mpss::utils::log_and_set_error("Key '{}' found in slot {} but failed to parse metadata: {}", name,
                                       utils::get_slot_name(match_slot), ykpiv_strerror(rc));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    const Algorithm algorithm = utils::yk_to_mpss_algorithm(metadata.algorithm);
    if (Algorithm::unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Key '{}' in slot {} has unsupported algorithm.", name,
                                       utils::get_slot_name(match_slot));
        return {.status = KeyProbeStatus::operational_error, .value = {}};
    }

    return {.status = KeyProbeStatus::found,
            .value = SlotInfo{.slot = match_slot, .algorithm = algorithm, .serial = serial_}};
}

std::uint8_t YubiKeyPIV::find_free_slot()
{
    // Prefer reusing slots that were previously deleted (dummy key with availability marker) over consuming a
    // genuinely empty slot.
    for (std::uint8_t slot : usable_slots)
    {
        const KeyProbeResult<std::string> label = read_slot_label(slot);
        if (KeyProbeStatus::found == label.status && available_slot_label == label.value)
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

std::optional<std::vector<std::uint32_t>> YubiKeyPIV::available_serials()
{
    if (thread_has_connection)
    {
        mpss::utils::log_and_set_error("Cannot list YubiKeys from a thread that holds a connection.");
        return std::nullopt;
    }

    // Listing serials connects to every reader in turn, and connecting to a device disturbs what a
    // session has established on it, a verified PIN among that. Connections take the bus shared and
    // this takes it exclusively, so no session is open anywhere while this scans.
    const std::unique_lock bus{device_locks().bus};
    return scan_readers_locked();
}

namespace
{

using PinDigest = std::array<unsigned char, SHA384_DIGEST_LENGTH>;

struct RejectedPins
{
    std::mutex mtx;
    // An HMAC key shorter than the digest would be the weakest part of the construction, so match it.
    std::array<unsigned char, SHA384_DIGEST_LENGTH> key{};
    // Every entry cost the device one retry to learn, so these lists stay short without a cap.
    std::map<std::uint32_t, std::vector<PinDigest>> by_serial;
};

[[nodiscard]]
RejectedPins &rejected_pins()
{
    // Immortal singleton state, for the same reason as the global logger: a host static destroyed after
    // this one would otherwise lock a destroyed mutex. The one-time allocation is reclaimed by the OS at
    // process exit. Scoped to this loaded copy of MPSS, so a host that links the static core into two
    // images gets one registry per image.
    static RejectedPins &state = []() -> RejectedPins & {
        auto *fresh = new RejectedPins{}; // NOLINT(cppcoreguidelines-owning-memory) - intentional immortal singleton,
                                          // never freed.
        // The key must stay secret: anyone holding it could recover a PIN from a stored fingerprint by
        // trying the few million candidates, so it is drawn from the private DRBG rather than the public
        // one.
        OSSL_LIB_CTX *host = mpss::utils::host_context();
        if (nullptr == host || 1 != RAND_priv_bytes_ex(host, fresh->key.data(), fresh->key.size(), 0))
        {
            // The key only raises the cost of recovering a PIN from a fingerprint. Losing it weakens that
            // and nothing else, so keep the lockout protection rather than trading it away.
            mpss::utils::log_warning(
                "Could not draw a random key for PIN fingerprints; lockout protection is unaffected.");
        }
        return *fresh;
    }();
    return state;
}

/**
 * @brief Fingerprint a PIN, or nothing if the digest could not be computed.
 *
 * Returning empty rather than a zero digest matters: zero digests would compare equal to one another, so
 * a PIN the device never saw could be taken for one it refused.
 */
[[nodiscard]]
std::optional<PinDigest> fingerprint_pin(const RejectedPins &state, std::string_view pin)
{
    OSSL_LIB_CTX *host = mpss::utils::host_context();
    if (nullptr == host)
    {
        return std::nullopt;
    }

    PinDigest digest{};
    std::size_t digest_size = 0;
    const unsigned char *result = EVP_Q_mac(host, "HMAC", "provider=default", "SHA384", nullptr, state.key.data(),
                                            state.key.size(), reinterpret_cast<const unsigned char *>(pin.data()),
                                            pin.size(), digest.data(), digest.size(), &digest_size);
    if (nullptr == result || digest.size() != digest_size)
    {
        return std::nullopt;
    }
    return digest;
}

/**
 * @brief Whether a PIN can be compared with what the device is actually given.
 *
 * The device receives a null-terminated string and so never sees anything past an embedded null. Two
 * values sharing a prefix would present identically while fingerprinting differently, and the second
 * would be offered as though the device had never refused it.
 */
[[nodiscard]]
bool is_comparable_pin(std::string_view pin)
{
    return !pin.empty() && std::string_view::npos == pin.find('\0');
}

[[nodiscard]]
bool same_digest(const PinDigest &lhs, const PinDigest &rhs)
{
    return 0 == CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size());
}

} // namespace

void remember_rejected_pin(std::uint32_t serial, std::string_view pin)
{
    if (!is_comparable_pin(pin))
    {
        return;
    }

    RejectedPins &state = rejected_pins();
    const std::scoped_lock lock{state.mtx};
    const std::optional<PinDigest> digest = fingerprint_pin(state, pin);
    if (!digest.has_value())
    {
        mpss::utils::log_warning("Could not fingerprint a rejected PIN; it may be presented to YubiKey {} again.",
                                 serial);
        return;
    }

    std::vector<PinDigest> &known = state.by_serial[serial];
    if (std::ranges::none_of(known, [&digest](const PinDigest &entry) {
            return same_digest(entry, *digest); // NOLINT(bugprone-unchecked-optional-access) - guarded above.
        }))
    {
        known.push_back(*digest); // NOLINT(bugprone-unchecked-optional-access) - guarded above.
    }
}

bool pin_already_rejected(std::uint32_t serial, std::string_view pin)
{
    if (!is_comparable_pin(pin))
    {
        return false;
    }

    RejectedPins &state = rejected_pins();
    const std::scoped_lock lock{state.mtx};
    const auto entry = state.by_serial.find(serial);
    if (state.by_serial.end() == entry)
    {
        return false;
    }

    const std::optional<PinDigest> digest = fingerprint_pin(state, pin);
    if (!digest.has_value())
    {
        // Without a comparable fingerprint there is no evidence this value was refused, and withholding it
        // anyway would block a PIN that may well be correct.
        return false;
    }

    return std::ranges::any_of(entry->second, [&digest](const PinDigest &known) {
        return same_digest(known, *digest); // NOLINT(bugprone-unchecked-optional-access) - guarded above.
    });
}

bool authenticate_pin_interactive(YubiKeyPIV &piv, std::string_view context)
{
    // Keep this handler and connection metadata fixed across retries and the matching result notifications.
    const std::shared_ptr<InteractionHandler> handler = mpss::GetInteractionHandler();
    const InteractionContext target = piv.interaction_context();
    mpss::SecureString last_failed_pin;
    mpss::PinStatus status = mpss::PinStatus::first_attempt;
    int retries = -1;
    const std::uint32_t serial = piv.get_serial();

    // Every way out of the loop reports a result, so a handler that opened UI while answering a request
    // always learns to take it down. These paths are already reporting a failure, and one of them runs
    // after the handler itself threw, so a throwing notification must not replace the real error.
    const auto report_not_attempted = [&handler, &retries, &target]() noexcept {
        try
        {
            const mpss::utils::InteractionHandlerScope in_handler;
            handler->notify_pin_result(target, mpss::PinResult::not_attempted, retries);
        }
        catch (...) // NOLINT(bugprone-empty-catch) - see above; nothing useful remains to report.
        {
        }
    };

    while (true)
    {
        // Ask the handler for a PIN. The handler controls the retry policy.
        std::optional<mpss::SecureString> pin_opt;
        try
        {
            const mpss::utils::InteractionHandlerScope in_handler;
            pin_opt = handler->request_pin(
                {.operation = context, .last_status = status, .retries_remaining = retries, .target = target});
        }
        catch (const std::exception &e)
        {
            mpss::utils::log_and_set_error("Interaction handler error: {}", e.what());
            report_not_attempted();
            return false;
        }

        if (!pin_opt || pin_opt->empty())
        {
            mpss::utils::log_and_set_error("YubiKey PIN not provided.");
            report_not_attempted();
            return false;
        }

        // Safety net: if the same PIN was already tried and failed, bail immediately to avoid burning
        // additional retry attempts (especially important when the PIN comes from an environment variable).
        if (!last_failed_pin.empty() && *pin_opt == last_failed_pin)
        {
            mpss::utils::log_and_set_error("Same PIN provided again after failure. Aborting to prevent lockout.");
            report_not_attempted();
            return false;
        }

        // The same applies across operations, which each ask for a PIN afresh: a value this device has
        // already refused would cost another retry and cannot succeed.
        if (pin_already_rejected(serial, *pin_opt))
        {
            mpss::utils::log_and_set_error("YubiKey {} already rejected this PIN. Aborting to prevent lockout.",
                                           serial);
            report_not_attempted();
            return false;
        }

        const mpss::PinResult result = piv.authenticate_pin(*pin_opt, retries);
        if (mpss::PinResult::wrong_pin == result)
        {
            // Recorded before the handler is notified, since a handler that throws or reenters must not be
            // able to lose the one fact that prevents the next operation spending another retry.
            remember_rejected_pin(serial, *pin_opt);
        }

        {
            const mpss::utils::InteractionHandlerScope in_handler;
            handler->notify_pin_result(target, result, retries);
        }

        if (mpss::PinResult::ok == result)
        {
            return true;
        }
        if (mpss::PinResult::locked == result || mpss::PinResult::error == result)
        {
            return false;
        }

        // Wrong PIN. Let the handler decide whether to retry.
        last_failed_pin = std::move(*pin_opt);
        status = mpss::PinStatus::wrong_pin;
    }
}

} // namespace mpss::impl::yubikey
