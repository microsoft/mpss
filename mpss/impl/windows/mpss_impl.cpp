// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/key_probe.h"
#include "mpss/impl/windows/win_keypair.h"
#include "mpss/impl/windows/win_utils.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <Windows.h>
#include <algorithm>
#include <cwchar>
#include <format>
#include <memory>
#include <ncrypt.h>
#include <optional>
#include <string>

namespace
{

using enum mpss::Algorithm;

// Legacy key spec. We only store signing keys.
constexpr DWORD key_spec = 0;

// The software KSP holds both VBS-isolated and plain software keys.
constexpr LPCWSTR tpm_provider_name = MS_PLATFORM_KEY_STORAGE_PROVIDER;
constexpr LPCWSTR software_ksp_name = MS_KEY_STORAGE_PROVIDER;

// Older SDK headers lack this flag.
#ifdef NCRYPT_REQUIRE_VBS_FLAG
constexpr DWORD require_vbs = NCRYPT_REQUIRE_VBS_FLAG;
#else
constexpr DWORD require_vbs = 0x00020000;
#endif

// Older SDK headers lack this property; it marks a key as VBS-isolated.
#ifndef NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY
#define NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY L"Virtual Iso"
#endif

// To open the key for the local machine, set this to NCRYPT_MACHINE_KEY_FLAG.
// Setting this to 0 opens the key for the current user.
constexpr DWORD key_open_mode = 0;

// A provider that a walk merely tried is not a failure of the operation the caller asked for, so its
// reason is kept for the caller's summary rather than announced. Only the caller knows whether a
// later provider answered. A caller that needs one particular provider passes speculative = false.
template <typename... Args>
void report_provider_failure(bool speculative, std::format_string<Args...> fmt, Args &&...args)
{
    if (!speculative)
    {
        mpss::utils::log_and_set_error(fmt, std::forward<Args>(args)...);
        return;
    }

    std::string message = std::format(fmt, std::forward<Args>(args)...);
    mpss::utils::log_debug(message);
    mpss::utils::set_error(std::move(message));
}

NCRYPT_PROV_HANDLE GetProvider(LPCWSTR provider_name, bool speculative, bool *contract_violation = nullptr)
{
    NCRYPT_PROV_HANDLE provider_handle = 0;

    // This function uses no extra flags.
    DWORD flags = 0;

    SECURITY_STATUS status = ::NCryptOpenStorageProvider(&provider_handle, provider_name, flags);
    if (ERROR_SUCCESS != status)
    {
        report_provider_failure(speculative, "NCryptOpenStorageProvider failed with error code {}.",
                                mpss::utils::to_hex(status));
        return 0;
    }

    if (0 == provider_handle)
    {
        // Success without a handle is the provider breaking its own contract, whoever asked.
        mpss::utils::log_and_set_error("Provider handle is null.");
        if (nullptr != contract_violation)
        {
            *contract_violation = true;
        }
        return 0;
    }

    return provider_handle;
}

// The three-outcome result of looking for a key in one provider. A handle-or-zero answer cannot
// distinguish a provider that holds no such key from one that could not be read, and creating a key
// on the strength of the second is what overwrites a key that is already there.
using OpenKeyResult = mpss::impl::KeyProbeResult<NCRYPT_KEY_HANDLE>;

OpenKeyResult OpenKeyInProvider(LPCWSTR provider_name, std::string_view name)
{
    using enum mpss::impl::KeyProbeStatus;

    bool contract_violation = false;
    NCRYPT_PROV_HANDLE provider_handle = GetProvider(provider_name, /* speculative */ true, &contract_violation);
    if (0 == provider_handle)
    {
        if (contract_violation)
        {
            // The provider reported success and then handed back nothing. That says nothing about
            // whether it holds the name, so the name is not free and not found either.
            return {.status = operational_error, .value = 0};
        }

        // A provider that cannot be opened holds no key that anything can reach, including this
        // backend's own creation path, so it does not make the name indeterminate. This is what a
        // machine without a TPM looks like, and creation has to keep working there. It is also an
        // assumption rather than a proof: a key another tool put in a provider this process cannot
        // open is invisible here, so clearing a name cannot speak for such a provider.
        return {.status = not_found, .value = 0};
    }

    SCOPE_GUARD(::NCryptFreeObject(provider_handle));
    NCRYPT_KEY_HANDLE key_handle = 0;
    const std::wstring wname(name.begin(), name.end());

    SECURITY_STATUS status = ::NCryptOpenKey(provider_handle, &key_handle, wname.c_str(), key_spec, key_open_mode);
    if (ERROR_SUCCESS != status)
    {
        // The provider answered, so only a status that positively confirms absence may be reported as
        // absence. NTE_BAD_KEYSET is the one status measured to mean that. The rest of the space cannot
        // be enumerated confidently: the two providers return different statuses for identical input, so
        // anything else leaves presence unknown and must not be read as a free name.
        if (static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET) == status)
        {
            return {.status = not_found, .value = 0};
        }

        mpss::utils::log_and_set_error("NCryptOpenKey failed with error code {}.", mpss::utils::to_hex(status));
        return {.status = operational_error, .value = 0};
    }

    // An earlier provider that did not hold the key left an error; clear it.
    mpss::utils::clear_error();
    return {.status = found, .value = key_handle};
}

OpenKeyResult OpenKeyTpm(std::string_view name)
{
    return OpenKeyInProvider(tpm_provider_name, name);
}

OpenKeyResult OpenKeySoftwareKsp(std::string_view name)
{
    return OpenKeyInProvider(software_ksp_name, name);
}

// Whether a Software KSP key is VBS-isolated. The property is unsupported on some providers and
// key handles, which is not the same as a key that is not isolated, and neither is the same as a
// read that failed outright.
enum class VirtualIsolation
{
    isolated,
    not_isolated,

    // The property exists but could not be read. The tier is unknown, so the operation fails
    // rather than reporting a tier that was never established.
    indeterminate
};

VirtualIsolation GetVirtualIsolation(NCRYPT_KEY_HANDLE key_handle)
{
    DWORD virtual_isolation = 0;
    DWORD output_size = 0;
    SECURITY_STATUS status = ::NCryptGetProperty(key_handle, NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY,
                                                 reinterpret_cast<PBYTE>(&virtual_isolation), sizeof(virtual_isolation),
                                                 &output_size, /* dwFlags */ 0);
    if (ERROR_SUCCESS == status)
    {
        return 0 != virtual_isolation ? VirtualIsolation::isolated : VirtualIsolation::not_isolated;
    }

    // A provider that does not implement the property cannot isolate keys, so the key is software
    // protected. Any other status means the answer is unknown.
    if (static_cast<SECURITY_STATUS>(NTE_NOT_SUPPORTED) == status)
    {
        return VirtualIsolation::not_isolated;
    }

    mpss::utils::log_and_set_error("NCryptGetProperty (virtual isolation) failed with error code {}.",
                                   mpss::utils::to_hex(status));
    return VirtualIsolation::indeterminate;
}

// Whether a key permits export of its private key. MPSS creates keys that prohibit it, so a key
// that allows it was put there by something else and its private material may be held elsewhere.
// The archiving flags count as permitting it: they allow the private key to be exported once.
enum class ExportPolicy
{
    prohibited,
    allowed,

    // The policy could not be read, so whether the key protects its private material is unknown.
    indeterminate
};

ExportPolicy GetExportPolicy(NCRYPT_KEY_HANDLE key_handle)
{
    using enum ExportPolicy;

    DWORD export_policy = 0;
    DWORD output_size = 0;
    SECURITY_STATUS status =
        ::NCryptGetProperty(key_handle, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                            sizeof(export_policy), &output_size, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptGetProperty (export policy) failed with error code {}.",
                                       mpss::utils::to_hex(status));
        return indeterminate;
    }

    constexpr DWORD export_allowed = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                                     NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG;
    return 0 != (export_policy & export_allowed) ? allowed : prohibited;
}

OpenKeyResult GetKey(std::string_view name, mpss::StorageTier *storage_tier)
{
    using enum mpss::impl::KeyProbeStatus;

    *storage_tier = mpss::StorageTier::unknown;

    // Every provider is asked before any answer is used. The providers keep separate namespaces, so
    // the same name can be held in both at once; returning the first that answered would let a key
    // planted in the provider this backend did not create in decide what the name means.
    OpenKeyResult tpm_key = OpenKeyTpm(name);
    OpenKeyResult ksp_key = OpenKeySoftwareKsp(name);

    const bool any_indeterminate = operational_error == tpm_key.status || operational_error == ksp_key.status;

    if (found == tpm_key.status && found == ksp_key.status)
    {
        ::NCryptFreeObject(tpm_key.value);
        ::NCryptFreeObject(ksp_key.value);
        mpss::utils::log_and_set_error(
            "Refusing to open key '{}': the name is held in both the TPM provider and the software KSP.", name);
        return {.status = operational_error, .value = 0};
    }

    // A rung that found nothing but could not say so in a code that positively confirms absence does
    // not veto a key another rung did find. The status space outside NTE_BAD_KEYSET is not
    // enumerable and differs between the two providers, so treating it as a veto would make a
    // legitimate key permanently unopenable on any host whose platform provider answers an
    // unfamiliar code -- the software-KSP keys this ladder exists to keep reachable. It only
    // constrains the verdict when the ladder found nothing at all.
    if (found == tpm_key.status)
    {
        *storage_tier = mpss::StorageTier::windows_tpm;
        return tpm_key;
    }

    if (found == ksp_key.status)
    {
        const VirtualIsolation isolation = GetVirtualIsolation(ksp_key.value);
        if (VirtualIsolation::indeterminate == isolation)
        {
            ::NCryptFreeObject(ksp_key.value);
            return {.status = operational_error, .value = 0};
        }

        if (VirtualIsolation::isolated == isolation)
        {
            // Isolation puts the key beyond the rest of the operating system, so this is not a
            // weak tier, but the hypervisor enforces it and what protects the key at rest depends
            // on Secure Boot and on a TPM being present, neither of which this can establish.
            // Reporting it as hardware backing would assert more than is known; the description
            // keeps the distinction from software storage.
            *storage_tier = mpss::StorageTier::windows_vbs;
        }
        else
        {
            *storage_tier = mpss::StorageTier::windows_software;
        }
        return ksp_key;
    }

    return {.status = any_indeterminate ? operational_error : not_found, .value = 0};
}

// Why a create attempt in one provider ended as it did, so the caller can decide whether trying the
// next provider is sensible.
enum class CreateOutcome
{
    created,

    // Another key already holds this name in this provider. The providers keep separate namespaces,
    // so the name may well be free in the next one, which is exactly why the walk has to stop.
    name_taken,

    // This provider could not make the key, but another one may: a machine with no TPM, or a TPM
    // that lacks the algorithm, still has to reach the providers below.
    unavailable
};

struct CreateKeyResult
{
    CreateOutcome outcome;
    NCRYPT_KEY_HANDLE value;
};

// Only the calls that address the name can find it taken. Measured on this platform: the create
// reports the collision, but a provider that defers the commit could report it at finalize instead.
CreateOutcome OutcomeFromStatus(SECURITY_STATUS status)
{
    return static_cast<SECURITY_STATUS>(NTE_EXISTS) == status ? CreateOutcome::name_taken : CreateOutcome::unavailable;
}

CreateKeyResult CreateKeyInProvider(LPCWSTR provider_name, std::string_view name, mpss::Algorithm algorithm,
                                    DWORD create_flags)
{
    mpss::impl::os::crypto_params const *const crypto = mpss::impl::os::utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        report_provider_failure(/* speculative */ true, "Unsupported algorithm '{}'.",
                                mpss::get_algorithm_info(algorithm).type_str);
        return {.outcome = CreateOutcome::unavailable, .value = 0};
    }

    NCRYPT_PROV_HANDLE provider_handle = GetProvider(provider_name, /* speculative */ true);
    if (0 == provider_handle)
    {
        return {.outcome = CreateOutcome::unavailable, .value = 0};
    }
    SCOPE_GUARD(::NCryptFreeObject(provider_handle));

    NCRYPT_KEY_HANDLE key_handle = 0;
    const std::wstring wname(name.begin(), name.end());

    SECURITY_STATUS status = ::NCryptCreatePersistedKey(provider_handle, &key_handle, crypto->key_type_name(),
                                                        wname.c_str(), key_spec, key_open_mode | create_flags);
    if (ERROR_SUCCESS != status)
    {
        report_provider_failure(/* speculative */ true, "NCryptCreatePersistedKey failed with error code {}.",
                                mpss::utils::to_hex(status));
        return {.outcome = OutcomeFromStatus(status), .value = 0};
    }

    // NCryptDeleteKey frees the handle on success, so only free it explicitly if the delete fails.
    SCOPE_GUARD({
        if (0 != key_handle)
        {
            if (ERROR_SUCCESS != ::NCryptDeleteKey(key_handle, /* dwFlags */ 0))
            {
                ::NCryptFreeObject(key_handle);
            }
        }
    });

    // Must be set before the key is finalized.
    DWORD export_policy = 0;
    status = ::NCryptSetProperty(key_handle, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                                 sizeof(export_policy), /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        report_provider_failure(/* speculative */ true, "NCryptSetProperty (export policy) failed with error code {}.",
                                mpss::utils::to_hex(status));

        // This call addresses a handle that is already ours, so it cannot be the one to discover
        // that the name belongs to someone else.
        return {.outcome = CreateOutcome::unavailable, .value = 0};
    }

    status = ::NCryptFinalizeKey(key_handle, /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        report_provider_failure(/* speculative */ true, "NCryptFinalizeKey failed with error code {}.",
                                mpss::utils::to_hex(status));
        return {.outcome = OutcomeFromStatus(status), .value = 0};
    }

    // An earlier provider left an error; clear it now that one has succeeded.
    mpss::utils::clear_error();

    const NCRYPT_KEY_HANDLE result = key_handle;
    key_handle = 0; // Disarm the cleanup guard: ownership passes to the caller.
    return {.outcome = CreateOutcome::created, .value = result};
}

// VBS and software share a CNG provider and differ only by the require_vbs flag.
CreateKeyResult CreateKeyTpm(std::string_view name, mpss::Algorithm algorithm)
{
    return CreateKeyInProvider(tpm_provider_name, name, algorithm, /* create_flags */ 0);
}

CreateKeyResult CreateKeyVbs(std::string_view name, mpss::Algorithm algorithm)
{
    return CreateKeyInProvider(software_ksp_name, name, algorithm, require_vbs);
}

CreateKeyResult CreateKeySoftware(std::string_view name, mpss::Algorithm algorithm)
{
    return CreateKeyInProvider(software_ksp_name, name, algorithm, /* create_flags */ 0);
}

// Reads a wide-string key property. Returns nullopt when the property cannot be read.
std::optional<std::wstring> GetWideStringProperty(NCRYPT_KEY_HANDLE key_handle, LPCWSTR property)
{
    DWORD byte_size = 0;
    SECURITY_STATUS status = ::NCryptGetProperty(key_handle, property,
                                                 /* pbOutput */ nullptr,
                                                 /* cbOutput */ 0, &byte_size,
                                                 /* dwFlags */ 0);
    if (ERROR_SUCCESS != status || 0 == byte_size)
    {
        return std::nullopt;
    }

    // The sizing call reports a count of bytes and std::wstring is sized in wchar_t, so convert by
    // dividing up rather than down: the buffer is then never smaller than the size CNG asked for.
    std::wstring value((byte_size + sizeof(wchar_t) - 1) / sizeof(wchar_t), L'\0');
    const DWORD capacity = mpss::utils::narrow_or_error<DWORD>(value.size() * sizeof(wchar_t));
    if (0 == capacity)
    {
        return std::nullopt;
    }

    status = ::NCryptGetProperty(key_handle, property, reinterpret_cast<PBYTE>(value.data()), capacity, &byte_size,
                                 /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        return std::nullopt;
    }

    // CNG returns a NUL-terminated string and counts the terminator in the size, so the buffer has
    // to hold it. Trim there, leaving just the value.
    value.resize(std::wcslen(value.c_str()));
    return value;
}

mpss::Algorithm GetAlgorithmFromName(NCRYPT_KEY_HANDLE key_handle)
{
    const std::optional<std::wstring> algorithm_name = GetWideStringProperty(key_handle, NCRYPT_ALGORITHM_PROPERTY);
    if (!algorithm_name.has_value())
    {
        mpss::utils::log_and_set_error("NCryptGetProperty (algorithm) failed.");
        return unsupported;
    }

    // The identifier names the algorithm and its group together.
    if (NCRYPT_ECDSA_P256_ALGORITHM == *algorithm_name)
    {
        return ecdsa_secp256r1_sha256;
    }
    if (NCRYPT_ECDSA_P384_ALGORITHM == *algorithm_name)
    {
        return ecdsa_secp384r1_sha384;
    }
    if (NCRYPT_ECDSA_P521_ALGORITHM == *algorithm_name)
    {
        return ecdsa_secp521r1_sha512;
    }

    // The identifier names only the algorithm; the group is carried in a separate property. Keys
    // created this way are ordinary signing keys and must keep working.
    if (BCRYPT_ECDSA_ALGORITHM == *algorithm_name)
    {
        const std::optional<std::wstring> group_name =
            GetWideStringProperty(key_handle, NCRYPT_ECC_CURVE_NAME_PROPERTY);
        if (!group_name.has_value())
        {
            mpss::utils::log_and_set_error("Key uses ECDSA but its named group could not be read.");
            return unsupported;
        }

        if (BCRYPT_ECC_CURVE_NISTP256 == *group_name)
        {
            return ecdsa_secp256r1_sha256;
        }
        if (BCRYPT_ECC_CURVE_NISTP384 == *group_name)
        {
            return ecdsa_secp384r1_sha384;
        }
        if (BCRYPT_ECC_CURVE_NISTP521 == *group_name)
        {
            return ecdsa_secp521r1_sha512;
        }

        mpss::utils::log_and_set_error("Key uses ECDSA with unsupported named group '{}'.",
                                       mpss::impl::os::utils::wide_to_utf8(*group_name));
        return unsupported;
    }

    // Everything else is refused, and the key size is deliberately not consulted. A size says
    // nothing about what a key may be used for: an ECDH key agreement key of the same size would
    // otherwise be accepted here and then used to sign.
    mpss::utils::log_and_set_error("Key algorithm '{}' is not supported.",
                                   mpss::impl::os::utils::wide_to_utf8(*algorithm_name));
    return unsupported;
}
} // namespace

namespace mpss::impl::os
{
using enum Algorithm;

using TryOpenKeyResult = mpss::impl::KeyProbeResult<std::unique_ptr<KeyPair>>;

TryOpenKeyResult try_open_key(std::string_view name)
{
    using enum mpss::impl::KeyProbeStatus;

    mpss::utils::log_trace("Attempting to open key '{}' on Windows backend.", name);

    Algorithm algorithm{unsupported};

    StorageTier storage_tier = StorageTier::unknown;
    OpenKeyResult found_key = GetKey(name, &storage_tier);
    if (found != found_key.status)
    {
        if (not_found == found_key.status)
        {
            // A clean negative carries no error: the ladder read every provider and none held the
            // key. GetProvider may have set one on a rung that failed before a later rung answered.
            mpss::utils::clear_error();
        }
        return {.status = found_key.status, .value = nullptr};
    }

    NCRYPT_KEY_HANDLE key_handle = found_key.value;
    SCOPE_GUARD({
        // Release if algorithm is not set, which means there was an error opening the key.
        if (unsupported == algorithm)
        {
            ::NCryptFreeObject(key_handle);
        }
    });

    // The key store is shared, so a name can be held by a key this backend did not create. MPSS
    // prohibits private key export on every key it creates, and a key that permits it cannot offer
    // the guarantee this backend exists to provide: its private material may already be held
    // somewhere else. Creation sets the policy; opening is where it is checked.
    const ExportPolicy export_policy = GetExportPolicy(key_handle);
    if (ExportPolicy::indeterminate == export_policy)
    {
        return {.status = operational_error, .value = nullptr};
    }
    if (ExportPolicy::allowed == export_policy)
    {
        mpss::utils::log_and_set_error("Key '{}' permits private key export.", name);
        return {.status = operational_error, .value = nullptr};
    }

    algorithm = GetAlgorithmFromName(key_handle);
    if (unsupported == algorithm)
    {
        // The key store holds this name; it just holds something this backend cannot use. That is
        // not the same as the name being free, and reporting it as free would let creation write a
        // second key of the same name into another provider. GetAlgorithmFromName has already
        // described what it found, which is the part that makes this diagnosable, so keep it and
        // add the key it applies to.
        const std::string reason{mpss::get_error()};
        mpss::utils::log_and_set_error("Key '{}' exists but cannot be used: {}", name, reason);
        return {.status = operational_error, .value = nullptr};
    }

    mpss::utils::log_trace("Key '{}' opened with {} storage.", name, get_storage_tier_info(storage_tier).description);
    return {.status = found, .value = std::make_unique<WindowsKeyPair>(algorithm, key_handle, storage_tier)};
}

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return {};
    }

    TryOpenKeyResult result = try_open_key(name);
    if (mpss::impl::KeyProbeStatus::not_found == result.status)
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
    }

    return std::move(result.value);
}

bool delete_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return false;
    }

    // Both providers are cleared, not just the one an open would have resolved to. The providers
    // keep separate namespaces, so a name can be held in both; leaving one behind would let a name
    // that could not be opened start resolving again, to whichever key survived.
    constexpr std::array providers = {tpm_provider_name, software_ksp_name};

    bool undetermined = false;
    std::size_t deleted = 0;

    for (LPCWSTR provider_name : providers)
    {
        OpenKeyResult opened = OpenKeyInProvider(provider_name, name);
        if (mpss::impl::KeyProbeStatus::not_found == opened.status)
        {
            continue;
        }
        if (mpss::impl::KeyProbeStatus::operational_error == opened.status)
        {
            // The provider may hold the name, so the name cannot be reported as cleared.
            undetermined = true;
            continue;
        }

        // NCryptDeleteKey frees the handle on success, so only free it explicitly if it fails.
        const SECURITY_STATUS status = ::NCryptDeleteKey(opened.value, /* dwFlags */ 0);
        if (ERROR_SUCCESS != status)
        {
            mpss::utils::log_and_set_error("NCryptDeleteKey failed with error code {}.", mpss::utils::to_hex(status));
            ::NCryptFreeObject(opened.value);
            undetermined = true;
            continue;
        }
        ++deleted;
    }

    if (undetermined)
    {
        mpss::utils::log_and_set_error("Could not clear key '{}' from every provider.", name);
        return false;
    }

    mpss::utils::clear_error();
    mpss::utils::log_trace("Cleared {} key(s) named '{}'.", deleted, name);
    return true;
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
    const std::string key_name{name};
    if (key_name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (KeyPolicy::none != policy)
    {
        mpss::utils::log_and_set_error("Windows backend does not support the requested key policy.");
        return nullptr;
    }

    // Fail if the key already exists or is already open.
    TryOpenKeyResult existing_key = try_open_key(name);
    if (mpss::impl::KeyProbeStatus::operational_error == existing_key.status)
    {
        // The store could not be read, so the name was never established to be free. Creating here
        // could write over a key that is already present.
        return nullptr;
    }
    if (mpss::impl::KeyProbeStatus::found == existing_key.status)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    struct key_storage_provider
    {
        CreateKeyResult (*create_key)(std::string_view, mpss::Algorithm);
        StorageTier storage_tier;

        // Whether the reported tier rests on per-key isolation evidence. The TPM provider is not
        // verified this way: it does not implement the isolation property, and holding the key is
        // itself the evidence. The software KSP holds both isolated and ordinary keys, so a key
        // created there must be classified by what the key reports, not by the flag that was asked
        // for. Isolation decides the description rather than this flag: only the TPM provider
        // reports hardware backing, for the reason the open path gives.
        bool verify_virtual_isolation;
    };

    // Strongest protection first: the first provider that creates a key wins.
    static constexpr std::array create_providers = {
        key_storage_provider{CreateKeyTpm, StorageTier::windows_tpm, false},
        key_storage_provider{CreateKeyVbs, StorageTier::windows_vbs, true},
        key_storage_provider{CreateKeySoftware, StorageTier::windows_software, false},
    };

    // Report why each provider failed; the reasons usually differ.
    std::string errors;
    for (const key_storage_provider &provider : create_providers)
    {
        mpss::utils::log_trace("Creating key '{}' with {} provider.", name,
                               get_storage_tier_info(provider.storage_tier).description);
        const CreateKeyResult created = provider.create_key(name, algorithm);
        const NCRYPT_KEY_HANDLE key_handle = created.value;
        if (0 != key_handle)
        {
            StorageTier storage_tier = provider.storage_tier;

            if (provider.verify_virtual_isolation)
            {
                const VirtualIsolation isolation = GetVirtualIsolation(key_handle);
                if (VirtualIsolation::indeterminate == isolation)
                {
                    // The tier could not be established, so the key is removed rather than reported
                    // at a tier that was never confirmed.
                    if (ERROR_SUCCESS != ::NCryptDeleteKey(key_handle, /* dwFlags */ 0))
                    {
                        ::NCryptFreeObject(key_handle);
                    }
                    return nullptr;
                }

                if (VirtualIsolation::not_isolated == isolation)
                {
                    // The key was created but is not isolated, so it is reported as what it is.
                    storage_tier = StorageTier::windows_software;
                }
            }

            mpss::utils::log_trace("Key '{}' created with '{}' storage.", name,
                                   get_storage_tier_info(storage_tier).description);
            return std::make_unique<WindowsKeyPair>(algorithm, key_handle, storage_tier);
        }

        if (!errors.empty())
        {
            errors += "; ";
        }
        errors +=
            std::string{get_storage_tier_info(provider.storage_tier).description} + ": " + mpss::utils::get_error();

        // The next provider's namespace may be free, and creating there plants a duplicate that a
        // later open could resolve to instead of this key. The create is the atomic reservation, so
        // its answer holds where the check above the walk can already be stale.
        if (CreateOutcome::name_taken == created.outcome)
        {
            mpss::utils::log_and_set_error("Key '{}' already exists.", name);
            return nullptr;
        }
    }

    mpss::utils::log_and_set_error("Failed to create key '{}': {}", name, errors);

    return nullptr;
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
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

    // Check compression indicator
    if (public_key[0] != std::byte{0x04})
    {
        mpss::utils::log_and_set_error("Invalid public key format.");
        return false;
    }

    // Get the algorithm info.
    const AlgorithmInfo info = get_algorithm_info(algorithm);

    // Get crypto parameters.
    crypto_params const *const crypto = utils::get_crypto_params(algorithm);
    if (nullptr == crypto)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", info.type_str);
        return false;
    }

    // Build the key blob.
    const DWORD pk_blob_size = sizeof(crypto_params::key_blob_t) + public_key.size() - 1;
    std::unique_ptr<BYTE[]> key_blob_buffer = std::make_unique<BYTE[]>(pk_blob_size);

    crypto_params::key_blob_t *key_blob = reinterpret_cast<crypto_params::key_blob_t *>(key_blob_buffer.get());
    key_blob->dwMagic = crypto->public_key_magic();
    key_blob->cbKey = mpss::utils::narrow_or_error<ULONG>((info.key_bits + 7) / 8);
    if (0 == key_blob->cbKey)
    {
        return false;
    }

    // Copy public key data to the blob.
    std::transform(public_key.begin() + 1, public_key.end(), key_blob_buffer.get() + sizeof(crypto_params::key_blob_t),
                   [](auto in) { return static_cast<BYTE>(in); });

    // Verification only needs the public key, so the software KSP is enough.
    NCRYPT_PROV_HANDLE provider = GetProvider(software_ksp_name, /* speculative */ false);
    if (0 == provider)
    {
        return false;
    }
    SCOPE_GUARD(::NCryptFreeObject(provider));

    // Import the public key.
    NCRYPT_KEY_HANDLE key_handle = 0;
    SECURITY_STATUS status =
        ::NCryptImportKey(provider,
                          /* hImportKey */ 0, crypto->public_key_blob_name(),
                          /* pParameterList */ nullptr, &key_handle, key_blob_buffer.get(), pk_blob_size,
                          /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        mpss::utils::log_and_set_error("NCryptImportKey failed with error code {}.", mpss::utils::to_hex(status));
        return false;
    }
    if (0 == key_handle)
    {
        mpss::utils::log_and_set_error("Failed to import key.");
        return false;
    }
    SCOPE_GUARD(::NCryptFreeObject(key_handle));

    // Extract the raw signature.
    std::size_t raw_sig_size = utils::decode_raw_signature(sig, algorithm, {});
    if (0 == raw_sig_size)
    {
        return false;
    }

    std::unique_ptr<std::byte[]> raw_sig = std::make_unique<std::byte[]>(raw_sig_size);
    std::span<std::byte> raw_sig_span(raw_sig.get(), raw_sig_size);
    raw_sig_size = utils::decode_raw_signature(sig, algorithm, raw_sig_span);

    const DWORD hash_size = mpss::utils::narrow_or_error<DWORD>(hash.size());
    if (0 == hash_size)
    {
        return false;
    }

    status = ::NCryptVerifySignature(key_handle,
                                     /* pPaddingInfo */ nullptr,
                                     reinterpret_cast<PBYTE>(const_cast<std::byte *>(hash.data())), hash_size,
                                     reinterpret_cast<PBYTE>(raw_sig.get()), raw_sig_size,
                                     /* dwFlags */ 0);
    if (ERROR_SUCCESS != status)
    {
        // This should not fail at this point unless the signature is invalid. The inputs are already validated.
        return false;
    }

    return true;
}

} // namespace mpss::impl::os
