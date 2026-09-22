// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/interaction_handler.h"
#include "mpss/key_policy.h"
#include "mpss/log.h"
#include "mpss/mpss.h"
#include "mpss/secure_types.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include "tests/compat_env.h"
#include "tests/test_key_names.h"
#if defined(__APPLE__) && !defined(MPSS_CORE_IS_SHARED)
#include "mpss/impl/apple/apple_api_wrapper.h"
#include "mpss/impl/apple/apple_result.h"
#include "mpss/impl/apple/apple_se_wrapper.h"
#include "mpss/impl/apple/apple_utils.h"
#endif
#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef MPSS_BACKEND_YUBIKEY
#include "mpss/impl/yubikey/yk_piv.h"
#ifndef MPSS_CORE_IS_SHARED
#include "mpss/impl/yubikey/yk_utils.h"
#endif
#endif

namespace mpss::tests
{

using namespace mpss;
using enum Algorithm;
using std::operator""s;

class MPSS : public ::testing::Test
{
  public:
    static void DeleteKey(const std::string &name)
    {
        // Try to delete the key from every available backend, not just the default one.
        // This ensures cleanup works regardless of the MPSS_DEFAULT_BACKEND setting.
        for (const char *backend : mpss::get_available_backends())
        {
            while (true)
            {
                std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Open(name, backend);
                if (nullptr == handle)
                {
                    break;
                }
                const bool deleted = handle->delete_key();
                if (!deleted)
                {
                    mpss::GetLogger()->error("Key could not be deleted from backend '{}': {}", backend,
                                             mpss::get_error());
                }
                ASSERT_TRUE(deleted);
            }
        }
    }

    static std::unique_ptr<mpss::KeyPair> CreateKey(std::string name, Algorithm algorithm)
    {
        // Create a key pair
        std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(std::move(name), algorithm);
        if (nullptr == handle)
        {
            mpss::GetLogger()->error("Key could not be created: {}", mpss::get_error());
        }
        else
        {
            mpss::GetLogger()->info("Key {} created in {}. Hardware backed: {}", name,
                                    handle->key_info().storage_description, handle->key_info().is_hardware_backed);
        }
        return handle;
    }
};

void SignAndVerify(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_key_"s + suffix.data());

    // Delete key if it exists
    MPSS::DeleteKey(key_name);

    // Create a key pair for testing
    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    // Test invalid hash size. A non-empty sig buffer is needed because an empty one
    // triggers the "query signature size" path, which does not validate the hash.
    const std::vector<std::byte> invalid_hash(hash_size - 1, static_cast<std::byte>('b'));
    std::vector<std::byte> dummy_sig(handle->sign_hash_size());
    std::size_t sig_size = handle->sign_hash(invalid_hash, dummy_sig);
    ASSERT_EQ(0, sig_size);

    // Sign the data
    const std::vector<std::byte> hash(hash_size, static_cast<std::byte>('a'));

    // First extract the size of the signature
    sig_size = handle->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    std::size_t written = handle->sign_hash(hash, signature);
    if (0 == written)
    {
        mpss::GetLogger()->error("Data could not be signed: {}", mpss::get_error());
    }
    ASSERT_GE(sig_size, written);

    // Verify the data. Signature needs to be resized to the actual size written.
    signature.resize(written);

    // Sign a second time to verify we get different signatures when signing the same data
    std::vector<std::byte> signature2(sig_size);
    written = handle->sign_hash(hash, signature2);
    if (0 == written)
    {
        mpss::GetLogger()->error("Data could not be signed second time: {}", mpss::get_error());
    }
    ASSERT_GE(sig_size, written);

    signature2.resize(written);
    ASSERT_NE(signature, signature2);

    // Verify first signature
    bool verified = handle->verify(hash, signature);
    if (!verified)
    {
        mpss::GetLogger()->error("Signature 1 could not be verified: {}", mpss::get_error());
    }
    ASSERT_TRUE(verified);

    // Verify second signature
    verified = handle->verify(hash, signature2);
    if (!verified)
    {
        mpss::GetLogger()->error("Signature 2 could not be verified: {}", mpss::get_error());
    }
    ASSERT_TRUE(verified);

    // Release the key pair
    handle->release_key();

    // Delete the key pair
    MPSS::DeleteKey(key_name);
}

void DoubleCreation(Algorithm algorithm, std::string_view suffix)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("creation_test_"s + suffix.data());

    // Delete key if it exists
    MPSS::DeleteKey(key_name);

    // Create the key pair
    std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    const std::size_t public_key_size = handle->extract_key({});
    ASSERT_NE(0, public_key_size);
    std::vector<std::byte> original_public_key(public_key_size);
    ASSERT_EQ(public_key_size, handle->extract_key(original_public_key));

    // Try to create the key pair again
    std::unique_ptr<mpss::KeyPair> handle2 = mpss::KeyPair::Create(key_name, algorithm);
    // It should fail
    ASSERT_EQ(nullptr, handle2);

    handle->release_key();
    handle.reset();

    std::unique_ptr<mpss::KeyPair> reopened_handle = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, reopened_handle);
    const std::size_t reopened_public_key_size = reopened_handle->extract_key({});
    ASSERT_EQ(public_key_size, reopened_public_key_size);
    std::vector<std::byte> reopened_public_key(reopened_public_key_size);
    ASSERT_EQ(reopened_public_key_size, reopened_handle->extract_key(reopened_public_key));
    ASSERT_EQ(original_public_key, reopened_public_key);

    ASSERT_TRUE(reopened_handle->delete_key());
}

// The protection a key reports must not change between creating it and reopening it by name. Which
// tier a key lands in depends on the machine, so the two reports are compared with each other
// rather than against a fixed expectation, and this holds on every backend.
void ReopenReportsTheSameProtection(Algorithm algorithm, std::string_view suffix)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_protection_"s + suffix.data());
    MPSS::DeleteKey(key_name);

    std::string created_storage;
    bool created_hardware_backed = false;
    mpss::StorageTier created_tier = mpss::StorageTier::unknown;
    {
        std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
        ASSERT_NE(nullptr, handle);
        ASSERT_NE(nullptr, handle->key_info().storage_description);

        created_storage = handle->key_info().storage_description;
        created_hardware_backed = handle->key_info().is_hardware_backed;
        created_tier = handle->key_info().storage_tier;

        // An empty description would satisfy the comparison below while telling a caller nothing.
        ASSERT_FALSE(created_storage.empty());
    }

    std::unique_ptr<mpss::KeyPair> reopened_handle = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, reopened_handle);
    ASSERT_NE(nullptr, reopened_handle->key_info().storage_description);

    EXPECT_EQ(created_tier, reopened_handle->key_info().storage_tier);
    EXPECT_EQ(created_storage, std::string{reopened_handle->key_info().storage_description});
    EXPECT_EQ(created_hardware_backed, reopened_handle->key_info().is_hardware_backed);

    ASSERT_TRUE(reopened_handle->delete_key());
}

// Releasing one handle must not disturb another handle open on the same name. A handle may be
// released explicitly and is released again when it is destroyed, so the second release must not
// give up a hold the first one already gave up.
void ReleaseDoesNotDisturbAnotherHandle(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("release_test_"s + suffix.data());
    MPSS::DeleteKey(key_name);

    {
        std::unique_ptr<mpss::KeyPair> created = MPSS::CreateKey(key_name, algorithm);
        ASSERT_NE(nullptr, created);
    }

    std::unique_ptr<mpss::KeyPair> first = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, first);
    std::unique_ptr<mpss::KeyPair> second = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, second);

    first->release_key();
    first.reset();

    const std::vector<std::byte> hash(hash_size, std::byte{0x2A});
    const std::size_t sig_size = second->sign_hash(hash, {});
    ASSERT_NE(0, sig_size);

    std::vector<std::byte> signature(sig_size);
    const std::size_t written = second->sign_hash(hash, signature);
    ASSERT_NE(0, written);
    signature.resize(written);
    ASSERT_TRUE(second->verify(hash, signature));

    ASSERT_TRUE(second->delete_key());
}

// A released handle is documented as no longer valid. Every operation on it must fail, on every
// backend, and releasing it again must be harmless.
void ReleasedHandleRefusesOperations(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("released_test_"s + suffix.data());
    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    const std::vector<std::byte> hash(hash_size, std::byte{0x2A});
    const std::size_t sig_size = handle->sign_hash(hash, {});
    ASSERT_NE(0, sig_size);
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = handle->sign_hash(hash, signature);
    ASSERT_NE(0, written);
    signature.resize(written);
    ASSERT_TRUE(handle->verify(hash, signature));

    EXPECT_TRUE(handle->release_key());

    EXPECT_TRUE(handle->release_key());

    std::vector<std::byte> second_signature(sig_size);
    EXPECT_EQ(0, handle->sign_hash(hash, second_signature));
    EXPECT_FALSE(handle->verify(hash, signature));
    std::vector<std::byte> public_key(handle->extract_key_size());
    EXPECT_EQ(0, handle->extract_key(public_key));
    EXPECT_FALSE(handle->delete_key());

    // The size requests spelled as an operation are refused with everything else, while the
    // accessors that derive a size from the algorithm alone still answer.
    EXPECT_EQ(0, handle->sign_hash(hash, {}));
    EXPECT_EQ(0, handle->extract_key({}));
    EXPECT_NE(0, handle->sign_hash_size());
    EXPECT_NE(0, handle->extract_key_size());

    // The handle still answers what it recorded when it was opened.
    EXPECT_EQ(algorithm, handle->algorithm());
    EXPECT_NE(nullptr, handle->key_info().storage_description);

    handle.reset();
    MPSS::DeleteKey(key_name);
}

// Deleting a name and creating it again while a handle to the old key is still alive must not let
// that handle's release disturb the new key. The stale handle is destroyed last, after the new one
// is already in use.
void StaleHandleDoesNotDisturbARecreatedKey(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("stale_test_"s + suffix.data());
    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> stale = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, stale);

    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> fresh = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, fresh);

    // The stale handle's release is charged against the key it was opened on, not the new one.
    stale.reset();

    const std::vector<std::byte> hash(hash_size, std::byte{0x2A});
    const std::size_t sig_size = fresh->sign_hash(hash, {});
    ASSERT_NE(0, sig_size);
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = fresh->sign_hash(hash, signature);
    ASSERT_NE(0, written);
    signature.resize(written);
    EXPECT_TRUE(fresh->verify(hash, signature));

    ASSERT_TRUE(fresh->delete_key());
}

// A handle that deleted its key is finished with it. It must refuse every operation afterwards,
// and must not reach a key created later under the same name.
void DeletingThroughAHandleInvalidatesIt(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("deleted_test_"s + suffix.data());
    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(handle->delete_key());

    const std::vector<std::byte> hash(hash_size, std::byte{0x2A});
    std::vector<std::byte> signature(handle->sign_hash_size());
    EXPECT_EQ(0, handle->sign_hash(hash, signature));
    std::vector<std::byte> public_key(handle->extract_key_size());
    EXPECT_EQ(0, handle->extract_key(public_key));
    EXPECT_FALSE(handle->delete_key());

    // The size requests never reach a backend, so they answer from the algorithm alone unless the
    // handle itself refuses. They are what makes this test speak for a backend whose operations
    // would fail after a deletion anyway.
    EXPECT_EQ(0, handle->sign_hash(hash, {}));
    EXPECT_EQ(0, handle->extract_key({}));

    // A key created again under the same name is a different key, and the old handle must not
    // reach it, least of all to delete it.
    std::unique_ptr<mpss::KeyPair> fresh = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, fresh);
    EXPECT_EQ(0, handle->sign_hash(hash, signature));
    EXPECT_FALSE(handle->delete_key());

    const std::size_t sig_size = fresh->sign_hash(hash, {});
    ASSERT_NE(0, sig_size);
    std::vector<std::byte> fresh_signature(sig_size);
    const std::size_t written = fresh->sign_hash(hash, fresh_signature);
    ASSERT_NE(0, written);
    fresh_signature.resize(written);
    EXPECT_TRUE(fresh->verify(hash, fresh_signature));

    ASSERT_TRUE(fresh->delete_key());
}

// A handle opened on one key must not reach a different key that later takes its name. The stale
// handle here is used rather than destroyed: it must refuse to sign, to extract and above all to
// delete, since deleting through it would destroy the key that replaced the one it opened.
void StaleHandleCannotReachAReplacementKey(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("reach_test_"s + suffix.data());
    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> original = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, original);

    std::unique_ptr<mpss::KeyPair> stale = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, stale);

    ASSERT_TRUE(original->delete_key());
    original.reset();

    std::unique_ptr<mpss::KeyPair> fresh = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, fresh);

    const std::size_t pk_size = fresh->extract_key_size();
    std::vector<std::byte> fresh_public_key(pk_size);
    ASSERT_EQ(pk_size, fresh->extract_key(fresh_public_key));

    const std::vector<std::byte> hash(hash_size, std::byte{0x2A});
    std::vector<std::byte> signature(stale->sign_hash_size());

    // The reason is documented, and it is deliberately not "missing": a caller told the key is
    // absent would reasonably create it, which is the one thing that must not follow from this.
    constexpr std::string_view superseded = "no longer the key this handle opened";

    EXPECT_EQ(0, stale->sign_hash(hash, signature));
    EXPECT_NE(std::string::npos, mpss::get_error().find(superseded)) << mpss::get_error();
    std::vector<std::byte> stale_public_key(pk_size);
    EXPECT_EQ(0, stale->extract_key(stale_public_key));
    EXPECT_NE(std::string::npos, mpss::get_error().find(superseded)) << mpss::get_error();
    EXPECT_FALSE(stale->delete_key());
    EXPECT_NE(std::string::npos, mpss::get_error().find(superseded)) << mpss::get_error();

    // The replacement is untouched by any of that.
    std::vector<std::byte> after(pk_size);
    ASSERT_EQ(pk_size, fresh->extract_key(after));
    EXPECT_EQ(fresh_public_key, after);

    const std::size_t sig_size = fresh->sign_hash(hash, {});
    ASSERT_NE(0, sig_size);
    std::vector<std::byte> fresh_signature(sig_size);
    const std::size_t written = fresh->sign_hash(hash, fresh_signature);
    ASSERT_NE(0, written);
    fresh_signature.resize(written);
    EXPECT_TRUE(fresh->verify(hash, fresh_signature));

    ASSERT_TRUE(fresh->delete_key());
}

TEST_F(MPSS, SignAndVerify256)
{
    SignAndVerify(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, SignAndVerify384)
{
    SignAndVerify(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, SignAndVerify521)
{
    SignAndVerify(ecdsa_secp521r1_sha512, "521", 64);
}

TEST(StorageTiers, EveryTierIsDescribedAndAnsweredOnce)
{
    std::set<mpss::StorageTier> seen;
    std::set<std::string> descriptions;
    for (const mpss::StorageTierInfo &info : mpss::storage_tiers)
    {
        EXPECT_TRUE(seen.insert(info.tier).second) << "a tier appears twice in the table";
        ASSERT_NE(nullptr, info.description);
        EXPECT_NE(0U, std::string(info.description).size());
        EXPECT_TRUE(descriptions.insert(info.description).second)
            << "two tiers share the description '" << info.description << "'";
    }
}

TEST(StorageTiers, KeyInfoReportsWhatTheTableHolds)
{
    for (const mpss::StorageTierInfo &info : mpss::storage_tiers)
    {
        const mpss::KeyInfo key_info{info.tier};
        EXPECT_EQ(info.tier, key_info.storage_tier);
        EXPECT_EQ(info.is_hardware_backed, key_info.is_hardware_backed);
        EXPECT_EQ(std::string(info.description), std::string(key_info.storage_description));
    }
}

// The rule the table encodes: hardware backing is claimed only for storage the platform vendor
// classifies as secure hardware. Virtualization Based Security and the software tiers are not that,
// and are the answers most likely to be changed by accident.
TEST(StorageTiers, OnlySecureHardwareTiersClaimHardwareBacking)
{
    using enum mpss::StorageTier;
    for (const mpss::StorageTier tier : {unknown, windows_software, windows_vbs, apple_keychain, android_software})
    {
        EXPECT_FALSE(mpss::get_storage_tier_info(tier).is_hardware_backed)
            << "tier " << static_cast<int>(tier) << " must not claim hardware backing";
    }
    for (const mpss::StorageTier tier : {windows_tpm, apple_secure_enclave, android_unknown_secure,
                                         android_trusted_environment, android_strongbox, yubikey_piv})
    {
        EXPECT_TRUE(mpss::get_storage_tier_info(tier).is_hardware_backed)
            << "tier " << static_cast<int>(tier) << " must claim hardware backing";
    }
}

TEST_F(MPSS, ReopenReportsTheSameProtection256)
{
    ReopenReportsTheSameProtection(ecdsa_secp256r1_sha256, "256");
}

TEST_F(MPSS, ReopenReportsTheSameProtection384)
{
    ReopenReportsTheSameProtection(ecdsa_secp384r1_sha384, "384");
}

TEST_F(MPSS, ReopenReportsTheSameProtection521)
{
    ReopenReportsTheSameProtection(ecdsa_secp521r1_sha512, "521");
}

TEST_F(MPSS, ReleaseDoesNotDisturbAnotherHandle256)
{
    ReleaseDoesNotDisturbAnotherHandle(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, ReleaseDoesNotDisturbAnotherHandle384)
{
    ReleaseDoesNotDisturbAnotherHandle(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, ReleaseDoesNotDisturbAnotherHandle521)
{
    ReleaseDoesNotDisturbAnotherHandle(ecdsa_secp521r1_sha512, "521", 64);
}

TEST_F(MPSS, ReleasedHandleRefusesOperations256)
{
    ReleasedHandleRefusesOperations(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, ReleasedHandleRefusesOperations384)
{
    ReleasedHandleRefusesOperations(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, ReleasedHandleRefusesOperations521)
{
    ReleasedHandleRefusesOperations(ecdsa_secp521r1_sha512, "521", 64);
}

TEST_F(MPSS, StaleHandleDoesNotDisturbARecreatedKey256)
{
    StaleHandleDoesNotDisturbARecreatedKey(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, StaleHandleDoesNotDisturbARecreatedKey384)
{
    StaleHandleDoesNotDisturbARecreatedKey(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, StaleHandleDoesNotDisturbARecreatedKey521)
{
    StaleHandleDoesNotDisturbARecreatedKey(ecdsa_secp521r1_sha512, "521", 64);
}

TEST_F(MPSS, DeletingThroughAHandleInvalidatesIt256)
{
    DeletingThroughAHandleInvalidatesIt(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, DeletingThroughAHandleInvalidatesIt384)
{
    DeletingThroughAHandleInvalidatesIt(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, DeletingThroughAHandleInvalidatesIt521)
{
    DeletingThroughAHandleInvalidatesIt(ecdsa_secp521r1_sha512, "521", 64);
}

TEST_F(MPSS, StaleHandleCannotReachAReplacementKey256)
{
    StaleHandleCannotReachAReplacementKey(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, StaleHandleCannotReachAReplacementKey384)
{
    StaleHandleCannotReachAReplacementKey(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, StaleHandleCannotReachAReplacementKey521)
{
    StaleHandleCannotReachAReplacementKey(ecdsa_secp521r1_sha512, "521", 64);
}

TEST_F(MPSS, DoubleCreation256)
{
    DoubleCreation(ecdsa_secp256r1_sha256, "256");
}

TEST_F(MPSS, DoubleCreation384)
{
    DoubleCreation(ecdsa_secp384r1_sha384, "384");
}

TEST_F(MPSS, DoubleCreation521)
{
    DoubleCreation(ecdsa_secp521r1_sha512, "521");
}

TEST_F(MPSS, DeleteByNameClearsAName)
{
    const std::string key_name = "delete_by_name_key";
    DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> key = CreateKey(key_name, ecdsa_secp256r1_sha256);
    if (nullptr == key)
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }
    key.reset();

    ASSERT_TRUE(mpss::KeyPair::Delete(key_name));

    // The open must fail because the name is free, not because it could not be read.
    ASSERT_EQ(nullptr, mpss::KeyPair::Open(key_name));
    EXPECT_TRUE(mpss::get_error().empty()) << mpss::get_error();
}

TEST_F(MPSS, DeleteByNameSucceedsWhenNothingIsStored)
{
    // The request is that the name hold no key. A name that already holds none satisfies it, so
    // repeating the call is not an error.
    const std::string key_name = "delete_by_name_absent_key";
    DeleteKey(key_name);

    EXPECT_TRUE(mpss::KeyPair::Delete(key_name));
    EXPECT_TRUE(mpss::KeyPair::Delete(key_name));
}

TEST_F(MPSS, RejectInvalidKeyNames)
{
    // Names must be 1-64 printable ASCII characters. Everything below is rejected by both Create
    // and Open before any backend is consulted, so these assertions are backend-independent. Each
    // invalid name would otherwise truncate or mangle at a C-string backend sink and could alias
    // onto a different stored key (embedded NUL is the primary aliasing vector).
    const std::vector<std::string> invalid_names = {
        ""s,                  // empty
        "a\0b"s,              // embedded NUL - truncates to "a" at every sink
        "a\001b"s,            // C0 control byte (octal escape keeps 'b' separate)
        "a\x7f"s,             // DEL
        "a\tb"s,              // tab (control)
        "a\nb"s,              // newline (control)
        "k\xC3\xA9y"s,        // non-ASCII (UTF-8 "key" with an accented e)
        std::string(65, 'a'), // exceeds the 64-character maximum
    };

    for (const std::string &name : invalid_names)
    {
        EXPECT_EQ(nullptr, mpss::KeyPair::Create(name, ecdsa_secp256r1_sha256))
            << "Create should reject invalid name (size " << name.size() << ")";
        EXPECT_FALSE(mpss::get_error().empty()) << "Create should report a rejected name as an error";
        EXPECT_EQ(nullptr, mpss::KeyPair::Open(name)) << "Open should reject invalid name (size " << name.size() << ")";
        EXPECT_FALSE(mpss::get_error().empty()) << "Open should report a rejected name as an error";
    }

    // The aliasing case: a name differing from a valid one only by a trailing NUL (+bytes) must not
    // be accepted, so it can never reach a backend as the truncated prefix "victim".
    EXPECT_EQ(nullptr, mpss::KeyPair::Create("victim\0x"s, ecdsa_secp256r1_sha256));
    EXPECT_EQ(nullptr, mpss::KeyPair::Open("victim\0x"s));
}

void GetKey(Algorithm algorithm, std::string_view suffix)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_key_2_"s + suffix.data());

    // Delete key if it exists
    MPSS::DeleteKey(key_name);

    // Create a key pair for testing
    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    // Get the key pair
    const std::size_t vk_size = handle->extract_key({});
    std::vector<std::byte> vk(vk_size);
    const std::size_t read = handle->extract_key(vk);
    if (0 == read)
    {
        mpss::GetLogger()->error("Key could not be retrieved: {}", mpss::get_error());
    }
    mpss::GetLogger()->info("VK size: {} read: {}", vk_size, read);
    ASSERT_EQ(vk_size, read);

    // Release the key pair handle
    handle->release_key();

    // Delete the key pair
    MPSS::DeleteKey(key_name);
}

void GetKeySmallBuffer(Algorithm algorithm, std::string_view suffix)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_key_3_"s + suffix.data());

    // Delete key if it exists
    MPSS::DeleteKey(key_name);

    // Create a key pair for testing
    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    // Get the key pair
    const std::size_t vk_size = handle->extract_key({});
    std::vector<std::byte> vk(vk_size - 1);
    const std::size_t read = handle->extract_key(vk);
    if (0 == read)
    {
        mpss::GetLogger()->error("Key could not be retrieved: {}", mpss::get_error());
    }
    ASSERT_EQ(0, read);

    // Release the key pair handle
    handle->release_key();

    // Delete the key pair
    MPSS::DeleteKey(key_name);
}

TEST_F(MPSS, GetKey256)
{
    GetKey(ecdsa_secp256r1_sha256, "256");
}

TEST_F(MPSS, GetKey384)
{
    GetKey(ecdsa_secp384r1_sha384, "384");
}

TEST_F(MPSS, GetKey521)
{
    GetKey(ecdsa_secp521r1_sha512, "521");
}

TEST_F(MPSS, GetKeySmallBuffer256)
{
    GetKeySmallBuffer(ecdsa_secp256r1_sha256, "256");
}

TEST_F(MPSS, GetKeySmallBuffer384)
{
    GetKeySmallBuffer(ecdsa_secp384r1_sha384, "384");
}

TEST_F(MPSS, GetKeySmallBuffer521)
{
    GetKeySmallBuffer(ecdsa_secp521r1_sha512, "521");
}

void VerifyStandaloneSignature(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_key_4_"s + suffix.data());
    // Delete key if it exists
    MPSS::DeleteKey(key_name);

    // Create a key pair for testing
    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    // Sign the data
    const std::vector<std::byte> hash(hash_size, static_cast<std::byte>('a'));
    const std::size_t sig_size = handle->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = handle->sign_hash(hash, signature);
    if (0 == written)
    {
        mpss::GetLogger()->error("Data could not be signed: {}", mpss::get_error());
    }
    ASSERT_GE(sig_size, written);
    signature.resize(written);

    // Get the public key
    const std::size_t vk_size = handle->extract_key({});
    std::vector<std::byte> vk(vk_size);
    const std::size_t read = handle->extract_key(vk);
    if (0 == read)
    {
        mpss::GetLogger()->error("Key could not be retrieved: {}", mpss::get_error());
    }
    mpss::GetLogger()->info("VK size: {}", vk_size);
    ASSERT_EQ(vk_size, read);

    // Release the key pair handle
    handle->release_key();

    // Delete the key pair
    MPSS::DeleteKey(key_name);

    // The key should not exist anymore, so try to verify with the public key
    const bool verified = mpss::verify(hash, vk, algorithm, signature);
    if (!verified)
    {
        mpss::GetLogger()->error("Data could not be verified: {}", mpss::get_error());
    }
    ASSERT_TRUE(verified);
}

TEST_F(MPSS, VerifyStandaloneSignature256)
{
    VerifyStandaloneSignature(ecdsa_secp256r1_sha256, "256", 32);
}

TEST_F(MPSS, VerifyStandaloneSignature384)
{
    VerifyStandaloneSignature(ecdsa_secp384r1_sha384, "384", 48);
}

TEST_F(MPSS, VerifyStandaloneSignature521)
{
    VerifyStandaloneSignature(ecdsa_secp521r1_sha512, "521", 64);
}

TEST_F(MPSS, DefaultBackendHonorsErrorContract)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("mpss_error_contract_test_key");
    DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> handle = CreateKey(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(mpss::get_error().empty());

    // An error left by a previous call does not survive into the next one. The first handle is
    // released before reopening, because a backend may key its live-handle state by key name.
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(""));
    EXPECT_FALSE(mpss::get_error().empty());
    handle.reset();
    handle = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(mpss::get_error().empty());

    const std::vector<std::byte> signed_hash(32, std::byte{'a'});
    const std::vector<std::byte> other_hash(32, std::byte{'b'});
    std::vector<std::byte> signature(handle->sign_hash_size());
    const std::size_t signature_size = handle->sign_hash(signed_hash, signature);
    ASSERT_NE(0, signature_size);
    EXPECT_TRUE(mpss::get_error().empty());
    signature.resize(signature_size);

    EXPECT_TRUE(mpss::get_error().empty());
    ASSERT_TRUE(handle->verify(signed_hash, signature));
    EXPECT_TRUE(mpss::get_error().empty());

    EXPECT_FALSE(handle->verify({}, {}));
    EXPECT_FALSE(mpss::get_error().empty());

    EXPECT_FALSE(handle->verify(other_hash, signature));
    EXPECT_TRUE(mpss::get_error().empty());

    // A wrong-size hash is malformed input, not a signature mismatch.
    const std::vector<std::byte> short_hash(16, std::byte{'a'});
    EXPECT_FALSE(handle->verify(short_hash, signature));
    EXPECT_FALSE(mpss::get_error().empty());

    std::vector<std::byte> sign_buffer(handle->sign_hash_size());
    EXPECT_EQ(0, handle->sign_hash(short_hash, sign_buffer));
    EXPECT_FALSE(mpss::get_error().empty());

    std::vector<std::byte> small_signature(handle->sign_hash_size() - 1);
    EXPECT_EQ(0, handle->sign_hash(signed_hash, small_signature));
    EXPECT_FALSE(mpss::get_error().empty());

    std::vector<std::byte> small_public_key(handle->extract_key_size() - 1);
    EXPECT_EQ(0, handle->extract_key(small_public_key));
    EXPECT_FALSE(mpss::get_error().empty());

    std::vector<std::byte> public_key(handle->extract_key_size());
    EXPECT_NE(0, handle->extract_key(public_key));
    EXPECT_TRUE(mpss::get_error().empty());

    ASSERT_TRUE(handle->delete_key());
    EXPECT_TRUE(mpss::get_error().empty());
    DeleteKey(key_name);
}

TEST(ErrorContract, HasErrorAndClearErrorTrackTheLastError)
{
    mpss::clear_error();
    EXPECT_FALSE(mpss::has_error());
    EXPECT_TRUE(mpss::get_error().empty());

    // A failed operation leaves an error that both accessors report. Reading it does not consume it.
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(""));
    EXPECT_TRUE(mpss::has_error());
    EXPECT_FALSE(mpss::get_error().empty());
    EXPECT_TRUE(mpss::has_error());

    mpss::clear_error();
    EXPECT_FALSE(mpss::has_error());
    EXPECT_TRUE(mpss::get_error().empty());

    // Clearing an already-clear error is harmless.
    mpss::clear_error();
    EXPECT_FALSE(mpss::has_error());
}

TEST(ErrorContract, AvailabilityQueriesHonorTheContract)
{
    // Prime the availability cache for every algorithm, so that the queries below take the
    // early-return path, where nothing else would incidentally overwrite a stale error.
    (void)mpss::get_available_algorithms();

    // Answering the question is the success, whichever way the answer goes, so a stale error does
    // not survive an availability query.
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(""));
    ASSERT_TRUE(mpss::has_error());
    (void)mpss::is_algorithm_available(ecdsa_secp256r1_sha256);
    EXPECT_FALSE(mpss::has_error());

    EXPECT_EQ(nullptr, mpss::KeyPair::Open(""));
    ASSERT_TRUE(mpss::has_error());
    (void)mpss::get_available_algorithms();
    EXPECT_FALSE(mpss::has_error());

    // The named-backend query is not cached, so it reaches the backend and, where the backend probes,
    // the scratch key that probe creates, signs with and deletes. That work is not the question the
    // caller asked, so it must not be reported either.
    const std::string default_backend = mpss::get_default_backend_name();
    ASSERT_FALSE(default_backend.empty());
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(""));
    ASSERT_TRUE(mpss::has_error());
    (void)mpss::is_algorithm_available(ecdsa_secp256r1_sha256, default_backend);
    EXPECT_FALSE(mpss::has_error());

    // A query that cannot be answered reports why. Each starts from a clean slate, so only the call
    // under test can account for the error.
    mpss::clear_error();
    EXPECT_FALSE(mpss::is_algorithm_available(mpss::Algorithm::unsupported));
    EXPECT_TRUE(mpss::has_error());

    mpss::clear_error();
    EXPECT_FALSE(mpss::is_algorithm_available(ecdsa_secp256r1_sha256, "no_such_backend"));
    EXPECT_TRUE(mpss::has_error());

    // Discovery accessors leave the last error alone, so a caller can name the backend while
    // composing a diagnostic about an earlier failure.
    (void)mpss::get_available_backends();
    (void)mpss::get_default_backend_name();
    EXPECT_TRUE(mpss::has_error());

    mpss::clear_error();
}

#ifndef MPSS_CORE_IS_SHARED
namespace
{
// A key pair whose operations always report an internal failure and then return the outcome they
// were constructed with. It stands in for a backend that reports a failed intermediate step and
// then recovers -- falling back to another storage tier, or moving on to another device.
class RecoveringKeyPair : public KeyPair
{
  public:
    static constexpr char internal_error[] = "Simulated internal failure.";

    explicit RecoveringKeyPair(bool succeed)
        : KeyPair(ecdsa_secp256r1_sha256, mpss::StorageTier::unknown), succeed_(succeed)
    {
    }

    ~RecoveringKeyPair() override
    {
        release_from_destructor();
    }

  protected:
    bool do_release_key() override
    {
        return true;
    }

    bool do_delete_key() override
    {
        utils::set_error(internal_error);
        return succeed_;
    }

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> /*hash*/, std::span<std::byte> sig) const override
    {
        utils::set_error(internal_error);
        return succeed_ ? sig.size() : 0;
    }

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> /*hash*/, std::span<const std::byte> /*sig*/) const override
    {
        utils::set_error(internal_error);
        return succeed_;
    }

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override
    {
        utils::set_error(internal_error);
        return succeed_ ? public_key.size() : 0;
    }

  private:
    bool succeed_;
};

// Counts how many times the backend release ran, so that a release racing itself can be held to
// running it once.
class CountingReleaseKeyPair : public KeyPair
{
  public:
    explicit CountingReleaseKeyPair(bool succeed = true)
        : KeyPair(ecdsa_secp256r1_sha256, mpss::StorageTier::unknown), succeed_(succeed)
    {
    }

    ~CountingReleaseKeyPair() override
    {
        release_from_destructor();
    }

    std::atomic<int> releases{0};

  protected:
    bool do_release_key() override
    {
        releases.fetch_add(1, std::memory_order_relaxed);
        return succeed_;
    }

    bool do_delete_key() override
    {
        return true;
    }

    [[nodiscard]]
    std::size_t do_sign_hash(std::span<const std::byte> /*hash*/, std::span<std::byte> sig) const override
    {
        return sig.size();
    }

    [[nodiscard]]
    bool do_verify(std::span<const std::byte> /*hash*/, std::span<const std::byte> /*sig*/) const override
    {
        return true;
    }

    [[nodiscard]]
    std::size_t do_extract_key(std::span<std::byte> public_key) const override
    {
        return public_key.size();
    }

  private:
    bool succeed_;
};
} // namespace

TEST(ErrorContract, SuccessDiscardsRecoveredInternalError)
{
    RecoveringKeyPair key_pair{true};
    const std::vector<std::byte> hash(32, std::byte{'a'});
    std::vector<std::byte> signature(key_pair.sign_hash_size());
    std::vector<std::byte> public_key(key_pair.extract_key_size());

    EXPECT_NE(0, key_pair.sign_hash(hash, signature));
    EXPECT_TRUE(mpss::get_error().empty());

    EXPECT_TRUE(key_pair.verify(hash, signature));
    EXPECT_TRUE(mpss::get_error().empty());

    EXPECT_NE(0, key_pair.extract_key(public_key));
    EXPECT_TRUE(mpss::get_error().empty());

    EXPECT_TRUE(key_pair.delete_key());
    EXPECT_TRUE(mpss::get_error().empty());
}

TEST(ErrorContract, FailureKeepsInternalError)
{
    RecoveringKeyPair key_pair{false};
    const std::vector<std::byte> hash(32, std::byte{'a'});
    std::vector<std::byte> signature(key_pair.sign_hash_size());
    std::vector<std::byte> public_key(key_pair.extract_key_size());

    EXPECT_EQ(0, key_pair.sign_hash(hash, signature));
    EXPECT_EQ(RecoveringKeyPair::internal_error, mpss::get_error());

    EXPECT_FALSE(key_pair.verify(hash, signature));
    EXPECT_EQ(RecoveringKeyPair::internal_error, mpss::get_error());

    EXPECT_EQ(0, key_pair.extract_key(public_key));
    EXPECT_EQ(RecoveringKeyPair::internal_error, mpss::get_error());

    EXPECT_FALSE(key_pair.delete_key());
    EXPECT_EQ(RecoveringKeyPair::internal_error, mpss::get_error());
}

// Releasing is a single decision rather than a test the caller makes and a set it performs later,
// so a crowd of threads asking at once reaches the backend once between them.
TEST(HandleThreadSafety, ConcurrentReleaseReachesTheBackendOnce)
{
    constexpr int thread_count = 16;

    CountingReleaseKeyPair handle;
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (int index = 0; index < thread_count; ++index)
    {
        threads.emplace_back([&handle, &go] {
            while (!go.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            EXPECT_TRUE(handle.release_key());
        });
    }

    go.store(true, std::memory_order_release);
    for (std::thread &thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(1, handle.releases.load(std::memory_order_relaxed));
}

// An interaction handler runs inside the locks the operation holding it already took, so a call
// made from one would wait on its own caller. Entry points refuse instead.
TEST(InteractionHandlerReentry, MpssRefusesWhileInsideAHandler)
{
    CountingReleaseKeyPair handle;
    const std::vector<std::byte> hash(32, std::byte{'a'});
    std::vector<std::byte> signature(handle.sign_hash_size());

    EXPECT_NE(0, handle.sign_hash(hash, signature));

    const mpss::utils::InteractionHandlerScope in_handler;
    EXPECT_TRUE(mpss::utils::in_interaction_handler());

    EXPECT_EQ(0, handle.sign_hash(hash, signature));
    EXPECT_FALSE(handle.verify(hash, signature));
    EXPECT_FALSE(handle.delete_key());
    EXPECT_FALSE(handle.release_key());
    EXPECT_EQ(nullptr, mpss::KeyPair::Open("mpss_reentry_test_key"));
    EXPECT_EQ(nullptr, mpss::KeyPair::Create("mpss_reentry_test_key", ecdsa_secp256r1_sha256));
    EXPECT_FALSE(mpss::KeyPair::Delete("mpss_reentry_test_key"));
    EXPECT_EQ(nullptr, mpss::KeyPair::Open("mpss_reentry_test_key", "os"));
    EXPECT_EQ(nullptr, mpss::KeyPair::Create("mpss_reentry_test_key", ecdsa_secp256r1_sha256, "os"));
    EXPECT_FALSE(mpss::KeyPair::Delete("mpss_reentry_test_key", "os"));
    const KeyLocation location{"os", "mpss_reentry_test_key", std::nullopt};
    EXPECT_EQ(nullptr, mpss::KeyPair::Open(location));
    EXPECT_EQ(nullptr, mpss::KeyPair::Create(location, ecdsa_secp256r1_sha256));
    EXPECT_FALSE(mpss::KeyPair::Delete(location));
    EXPECT_EQ("MPSS cannot be called from an interaction handler.", mpss::get_error());

    // Refused rather than released, so the backend was never reached.
    EXPECT_EQ(0, handle.releases.load(std::memory_order_relaxed));
}

// A release runs once, so what that one attempt reported is what every later caller is told. A
// handle that could not give up what it held must not report success to the next asker.
TEST(HandleThreadSafety, AFailedReleaseIsReportedToEveryCaller)
{
    CountingReleaseKeyPair handle{false};

    EXPECT_FALSE(handle.release_key());
    EXPECT_FALSE(handle.release_key());
    EXPECT_EQ(1, handle.releases.load(std::memory_order_relaxed));
}
#endif

// Signing, verifying and extracting take the handle in shared mode, so several threads may be
// inside one handle at once and every one of them must come out with a usable answer.
TEST_F(MPSS, ConcurrentSigningOnOneHandle)
{
    constexpr int thread_count = 8;
    constexpr int per_thread = 10;
    constexpr Algorithm algorithm = ecdsa_secp256r1_sha256;

    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("concurrent_sign");
    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    std::atomic<int> signed_count{0};
    std::atomic<int> verified_count{0};
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (int index = 0; index < thread_count; ++index)
    {
        threads.emplace_back([&handle, &signed_count, &verified_count, &go, index] {
            while (!go.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }

            const std::vector<std::byte> hash(32, static_cast<std::byte>(index));
            std::vector<std::byte> signature(handle->sign_hash_size());
            for (int round = 0; round < per_thread; ++round)
            {
                const std::size_t written = handle->sign_hash(hash, signature);
                if (0 == written)
                {
                    continue;
                }
                signed_count.fetch_add(1, std::memory_order_relaxed);
                if (handle->verify(hash, std::span{signature}.first(written)))
                {
                    verified_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (std::thread &thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(thread_count * per_thread, signed_count.load(std::memory_order_relaxed));
    EXPECT_EQ(thread_count * per_thread, verified_count.load(std::memory_order_relaxed));

    MPSS::DeleteKey(key_name);
}

// A name is the only identity the library has, so creating one is a decision made once. Threads
// racing to create the same absent name must not all find it absent and all create it, which on a
// backend with two storage tiers leaves the name ambiguous and unopenable.
TEST_F(MPSS, ConcurrentCreateOfOneNameProducesOneKey)
{
    constexpr int thread_count = 8;

    // Two algorithms, because a backend may keep them in different places: one name created twice
    // at once could otherwise land in two tiers at once and afterwards open from neither.
    constexpr std::array<Algorithm, 2> algorithms{ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384};
    if (!std::ranges::all_of(algorithms, [](Algorithm value) { return mpss::is_algorithm_available(value); }))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("concurrent_create");
    MPSS::DeleteKey(key_name);

    std::atomic<int> created{0};
    std::atomic<bool> go{false};
    std::vector<std::unique_ptr<mpss::KeyPair>> handles(thread_count);
    std::vector<std::thread> threads;
    threads.reserve(thread_count);

    for (int index = 0; index < thread_count; ++index)
    {
        threads.emplace_back([&handles, &created, &go, &key_name, &algorithms, index] {
            while (!go.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            handles[index] =
                mpss::KeyPair::Create(key_name, algorithms.at(static_cast<std::size_t>(index) % algorithms.size()));
            if (nullptr != handles[index])
            {
                created.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    go.store(true, std::memory_order_release);
    for (std::thread &thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(1, created.load(std::memory_order_relaxed));

    handles.clear();
    MPSS::DeleteKey(key_name);
}

#if defined(__APPLE__) && !defined(MPSS_CORE_IS_SHARED)
TEST(AppleErrorPropagation, MissingOpenHasNoErrorDetail)
{
    constexpr char key_name[] = "mpss_apple_missing_error_test_key";
    EXPECT_TRUE(MPSS_DeleteKey(key_name));
    EXPECT_TRUE(mpss::impl::os::utils::take_keychain_error().empty());
    (void)MPSS_SE_RemoveExistingKey(key_name);

    int bit_size = 0;
    std::uint64_t generation = 0;
    EXPECT_EQ(MPSS_APPLE_RESULT_EXPECTED_NEGATIVE, MPSS_OpenExistingKey(key_name, &bit_size, &generation, nullptr));
    EXPECT_TRUE(mpss::impl::os::utils::take_keychain_error().empty());

    EXPECT_EQ(MPSS_APPLE_RESULT_EXPECTED_NEGATIVE, MPSS_SE_OpenExistingKey(key_name, &generation));
    EXPECT_TRUE(mpss::impl::os::utils::take_secure_enclave_error().empty());

    EXPECT_EQ(nullptr, mpss::KeyPair::Open(key_name));
    EXPECT_TRUE(mpss::get_error().empty());
}

TEST(AppleErrorPropagation, WrapperErrorsAreConsumedOnce)
{
    const std::array<std::uint8_t, 32> hash{};
    const std::array<std::uint8_t, 1> malformed_public_key{};
    const std::array<std::uint8_t, 1> malformed_signature{};

    EXPECT_EQ(MPSS_APPLE_RESULT_OPERATIONAL_ERROR,
              MPSS_VerifyStandaloneSignature(static_cast<int>(ecdsa_secp256r1_sha256), hash.data(), hash.size(),
                                             malformed_public_key.data(), malformed_public_key.size(),
                                             malformed_signature.data(), malformed_signature.size()));
    EXPECT_FALSE(mpss::impl::os::utils::take_keychain_error().empty());
    EXPECT_TRUE(mpss::impl::os::utils::take_keychain_error().empty());

    EXPECT_EQ(MPSS_APPLE_RESULT_OPERATIONAL_ERROR,
              MPSS_SE_VerifyStandaloneSignature(malformed_public_key.data(), malformed_public_key.size(), hash.data(),
                                                hash.size(), malformed_signature.data(), malformed_signature.size()));
    EXPECT_FALSE(mpss::impl::os::utils::take_secure_enclave_error().empty());
    EXPECT_TRUE(mpss::impl::os::utils::take_secure_enclave_error().empty());

    int bit_size = 0;
    std::uint64_t generation = 0;
    EXPECT_EQ(MPSS_APPLE_RESULT_OPERATIONAL_ERROR, MPSS_OpenExistingKey(nullptr, &bit_size, &generation, nullptr));
    EXPECT_FALSE(mpss::impl::os::utils::take_keychain_error().empty());

    const char unicode_key_name[] = {static_cast<char>(0xC3), static_cast<char>(0xA9), '\0'};
    std::array<std::uint8_t, 72> signature{};
    std::size_t signature_size = signature.size();
    EXPECT_FALSE(
        MPSS_SE_Sign(unicode_key_name, hash.data(), hash.size(), signature.data(), &signature_size, generation));
    const std::string unicode_error = mpss::impl::os::utils::take_secure_enclave_error();
    EXPECT_NE(std::string::npos, unicode_error.find(unicode_key_name));
}

TEST_F(MPSS, DISABLED_SecureEnclaveUserPresenceInteractiveSigning)
{
    if (!MPSS_SE_SecureEnclaveIsSupported())
    {
        GTEST_SKIP() << "Secure Enclave not available";
    }

    const std::string key_name = test_key_name("mpss_apple_user_presence_signing_test");
    DeleteKey(key_name);
    std::unique_ptr<mpss::KeyPair> handle =
        mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "os", KeyPolicy::apple_secure_enclave_user_presence);
    ASSERT_NE(nullptr, handle);
    handle.reset();

    handle = mpss::KeyPair::Open(key_name, "os");
    ASSERT_NE(nullptr, handle);
    const std::vector<std::byte> hash(32, std::byte{'a'});
    std::vector<std::byte> signature(handle->sign_hash_size());
    const std::size_t signature_size = handle->sign_hash(hash, signature);
    EXPECT_NE(0, signature_size);
    if (0 != signature_size)
    {
        signature.resize(signature_size);
        EXPECT_TRUE(handle->verify(hash, signature));
    }
    EXPECT_TRUE(handle->delete_key());
}
#endif

#ifdef __APPLE__
TEST_F(MPSS, SecureEnclaveUserPresenceFailsWithoutSupportedKey)
{
    const std::string key_name = test_key_name("mpss_apple_user_presence_unsupported_test");
    DeleteKey(key_name);
    EXPECT_EQ(nullptr, mpss::KeyPair::Create(key_name, ecdsa_secp384r1_sha384, "os",
                                             KeyPolicy::apple_secure_enclave_user_presence));
    EXPECT_NE(std::string::npos, mpss::get_error().find("requires ecdsa_secp256r1_sha256"));
}

TEST_F(MPSS, AppleBackendRejectsUnsupportedKeyPolicy)
{
    const std::string key_name = test_key_name("mpss_apple_unsupported_policy_test");
    DeleteKey(key_name);
    EXPECT_EQ(nullptr, mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "os", static_cast<KeyPolicy>(1ULL)));
    EXPECT_NE(std::string::npos, mpss::get_error().find("does not support the requested key policy"));
}

TEST_F(MPSS, InvalidSignatureClearsOperationalError)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("mpss_apple_invalid_signature_error_test");
    DeleteKey(key_name);
    std::unique_ptr<mpss::KeyPair> handle = CreateKey(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle);

    const std::vector<std::byte> signed_hash(32, std::byte{'a'});
    const std::vector<std::byte> other_hash(32, std::byte{'b'});
    std::vector<std::byte> signature(handle->sign_hash_size());
    const std::size_t signature_size = handle->sign_hash(signed_hash, signature);
    ASSERT_NE(0, signature_size);
    signature.resize(signature_size);

    std::vector<std::byte> public_key(handle->extract_key_size());
    ASSERT_EQ(public_key.size(), handle->extract_key(public_key));
    ASSERT_TRUE(mpss::verify(signed_hash, public_key, ecdsa_secp256r1_sha256, signature));

    std::vector<std::byte> malformed_public_key = public_key;
    malformed_public_key.front() ^= std::byte{0xFF};
    ASSERT_FALSE(mpss::verify(signed_hash, malformed_public_key, ecdsa_secp256r1_sha256, signature));
    ASSERT_FALSE(mpss::get_error().empty());

    EXPECT_FALSE(mpss::verify(other_hash, public_key, ecdsa_secp256r1_sha256, signature));
    EXPECT_TRUE(mpss::get_error().empty());

    ASSERT_TRUE(handle->delete_key());
}

TEST_F(MPSS, VerificationErrorSurvivesKeyDestruction)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("mpss_apple_destroyed_key_error_test");
    DeleteKey(key_name);
    std::unique_ptr<mpss::KeyPair> handle = CreateKey(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle);

    ASSERT_FALSE(handle->verify({}, {}));
    const std::string verification_error = mpss::get_error();
    ASSERT_FALSE(verification_error.empty());

    handle.reset();
    EXPECT_EQ(verification_error, mpss::get_error());
    DeleteKey(key_name);
}
#endif

#if defined(__ANDROID__) || defined(_WIN32)
TEST_F(MPSS, OSBackendRejectsUnsupportedKeyPolicy)
{
    const std::string key_name = test_key_name("mpss_os_unsupported_policy_test");
    DeleteKey(key_name);
    EXPECT_EQ(nullptr, mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "os",
                                             KeyPolicy::apple_secure_enclave_user_presence));
    EXPECT_NE(std::string::npos, mpss::get_error().find("does not support the requested key policy"));
}
#endif

TEST(MPSSTests, IsAlgorithmSupported)
{
    ASSERT_NO_THROW({
        const bool supported = mpss::is_algorithm_available(ecdsa_secp256r1_sha256);
        mpss::GetLogger()->info("Algorithm ecdsa_secp256r1_sha256 supported: {}", supported);
    });
    ASSERT_NO_THROW({
        const bool supported = mpss::is_algorithm_available(ecdsa_secp384r1_sha384);
        mpss::GetLogger()->info("Algorithm ecdsa_secp384r1_sha384 supported: {}", supported);
    });
    ASSERT_NO_THROW({
        const bool supported = mpss::is_algorithm_available(ecdsa_secp521r1_sha512);
        mpss::GetLogger()->info("Algorithm ecdsa_secp521r1_sha512 supported: {}", supported);
    });
}

TEST(MPSSTests, IsAlgorithmSupported256)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }
}

// --- Backend discovery and explicit backend API tests ---

TEST(BackendTest, GetAvailableBackends)
{
    const auto backends = mpss::get_available_backends();
    EXPECT_FALSE(backends.empty());
    for (const auto &name : backends)
    {
        mpss::GetLogger()->info("Available backend: {}", name);
    }
}

TEST(BackendTest, GetDefaultBackendName)
{
    const char *const name = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, name);
    EXPECT_GT(std::strlen(name), std::size_t{0});
    mpss::GetLogger()->info("Default backend: {}", name);
}

TEST(KeyLocationTest, RejectsInvalidLocationsBeforeDispatch)
{
    const std::array<KeyLocation, 3> invalid = {KeyLocation{"", "key", std::nullopt},
                                                KeyLocation{"os", "", std::nullopt},
                                                KeyLocation{"yubikey", "key", std::string{}}};
    for (const auto &location : invalid)
    {
        EXPECT_EQ(nullptr, KeyPair::Create(location, ecdsa_secp256r1_sha256));
        EXPECT_TRUE(mpss::has_error());
        const std::string error = mpss::get_error();
        EXPECT_EQ(nullptr, KeyPair::Open(location));
        EXPECT_TRUE(mpss::has_error());
        EXPECT_FALSE(KeyPair::Delete(location));
        EXPECT_TRUE(mpss::has_error());
        if (!location.device_id)
        {
            EXPECT_EQ(nullptr, KeyPair::Create(location.name, ecdsa_secp256r1_sha256, location.backend_name));
            EXPECT_EQ(error, mpss::get_error());
            EXPECT_EQ(nullptr, KeyPair::Open(location.name, location.backend_name));
            EXPECT_EQ(error, mpss::get_error());
            EXPECT_FALSE(KeyPair::Delete(location.name, location.backend_name));
            EXPECT_EQ(error, mpss::get_error());
        }
    }
}

TEST(KeyLocationTest, UnknownBackendCannotListDevices)
{
    EXPECT_FALSE(mpss::get_available_devices("unknown-backend").has_value());
    EXPECT_TRUE(mpss::has_error());
}

TEST(KeyLocationTest, OSStorageRejectsDeviceSelection)
{
    const auto backends = mpss::get_available_backends();
    if (std::ranges::none_of(backends, [](const char *name) { return "os" == std::string_view{name}; }))
    {
        GTEST_SKIP() << "OS backend is not built.";
    }
    const auto devices = mpss::get_available_devices("os");
    ASSERT_TRUE(devices.has_value());
    EXPECT_TRUE(devices->empty());
    EXPECT_FALSE(mpss::has_error());

    const KeyLocation location{"os", test_key_name("device_selector"), "123"};
    EXPECT_EQ(nullptr, KeyPair::Create(location, ecdsa_secp256r1_sha256));
    EXPECT_TRUE(mpss::has_error());
    EXPECT_EQ(nullptr, KeyPair::Open(location));
    EXPECT_TRUE(mpss::has_error());
    EXPECT_FALSE(KeyPair::Delete(location));
    EXPECT_TRUE(mpss::has_error());
}

TEST(KeyReferenceTest, RejectsUnsupportedAlgorithmAndInvalidPublicKeySize)
{
    KeyReference reference{{"unknown-backend", "key", std::nullopt}, unsupported, {}};
    EXPECT_EQ(nullptr, KeyPair::Open(reference));
    EXPECT_NE(std::string::npos, mpss::get_error().find("public key size"));

    reference.algorithm = ecdsa_secp256r1_sha256;
    for (const std::size_t size : {std::size_t{0}, std::size_t{64}, std::size_t{66}})
    {
        reference.public_key.resize(size);
        EXPECT_EQ(nullptr, KeyPair::Open(reference));
        EXPECT_NE(std::string::npos, mpss::get_error().find("public key size"));
    }
}

TEST_F(MPSS, ResolvedLocationAndReferenceRoundTrip)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }
    const std::string name = test_key_name("reference_roundtrip");
    auto original = KeyPair::Create(name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, original) << mpss::get_error();
    SCOPE_GUARD(static_cast<void>(original->delete_key()));

    const auto location = original->location();
    EXPECT_EQ(name, location.name);
    EXPECT_EQ(std::string{original->backend_name()}, location.backend_name);
    EXPECT_EQ("yubikey" == location.backend_name, location.device_id.has_value());

    const auto captured = original->reference();
    ASSERT_TRUE(captured.has_value()) << mpss::get_error();
    KeyReference reference = *captured;
    EXPECT_EQ(location.name, reference.location.name);
    EXPECT_EQ(location.device_id, reference.location.device_id);
    auto reopened = KeyPair::Open(reference);
    ASSERT_NE(nullptr, reopened) << mpss::get_error();
    EXPECT_EQ(location.device_id, reopened->location().device_id);
    EXPECT_EQ(location.backend_name, reopened->location().backend_name);
    EXPECT_EQ(location.name, reopened->location().name);

    auto wrong_key = reference;
    wrong_key.public_key.back() ^= std::byte{1};
    EXPECT_EQ(nullptr, KeyPair::Open(wrong_key));
    EXPECT_TRUE(mpss::has_error());

    auto wrong_algorithm = reference;
    wrong_algorithm.algorithm = ecdsa_secp384r1_sha384;
    wrong_algorithm.public_key.resize(97);
    EXPECT_EQ(nullptr, KeyPair::Open(wrong_algorithm));
    EXPECT_TRUE(mpss::has_error());

    const auto expected = reference.public_key;
    reference.public_key.assign(reference.public_key.size(), std::byte{0});
    std::vector<std::byte> extracted(expected.size());
    ASSERT_EQ(extracted.size(), reopened->extract_key(extracted));
    EXPECT_EQ(expected, extracted);
    const std::vector<std::byte> hash(32, std::byte{0x5A});
    std::vector<std::byte> signature(reopened->sign_hash_size());
    const auto written = reopened->sign_hash(hash, signature);
    ASSERT_GT(written, std::size_t{0}) << mpss::get_error();
    ASSERT_LE(written, signature.size());
    EXPECT_TRUE(mpss::verify(hash, expected, reopened->algorithm(),
                             std::span<const std::byte>{signature}.first(written), location.backend_name));
    EXPECT_TRUE(reopened->release_key());
    EXPECT_FALSE(reopened->reference().has_value());
    EXPECT_TRUE(mpss::has_error());
    EXPECT_EQ(location.device_id, reopened->location().device_id);
    EXPECT_EQ(location.name, reopened->location().name);
}

TEST(BackendTest, CreateKeyWithExplicitBackend)
{
    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = test_key_name("test_explicit_key");
    MPSS::DeleteKey(key_name);

    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, default_backend);
    EXPECT_NE(nullptr, key);

    if (nullptr != key)
    {
        key->delete_key();
    }
}

TEST(BackendTest, OpenKeyWithExplicitBackend)
{
    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = test_key_name("test_explicit_open_key");
    MPSS::DeleteKey(key_name);

    // Create a key first.
    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, default_backend);
    ASSERT_NE(nullptr, key);
    key.reset();

    // Open the key using the explicit backend.
    auto opened = mpss::KeyPair::Open(key_name, default_backend);
    EXPECT_NE(nullptr, opened);

    if (nullptr != opened)
    {
        opened->delete_key();
    }
}

TEST(BackendTest, BackendNameSetOnCreate)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = test_key_name("test_backend_name_create");
    MPSS::DeleteKey(key_name);

    // Create with default backend.
    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);
    EXPECT_STREQ(default_backend, key->backend_name());
    key->delete_key();
}

TEST(BackendTest, BackendNameSetOnCreateExplicit)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = test_key_name("test_backend_name_create_explicit");
    MPSS::DeleteKey(key_name);

    // Create with explicit backend.
    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, default_backend);
    ASSERT_NE(nullptr, key);
    EXPECT_STREQ(default_backend, key->backend_name());
    key->delete_key();
}

TEST(BackendTest, BackendNameSetOnOpen)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = test_key_name("test_backend_name_open");
    MPSS::DeleteKey(key_name);

    // Create, then reopen with default backend.
    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);
    key.reset();

    auto opened = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, opened);
    EXPECT_STREQ(default_backend, opened->backend_name());
    opened->delete_key();
}

TEST(BackendTest, BackendNameSetOnOpenExplicit)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = test_key_name("test_backend_name_open_explicit");
    MPSS::DeleteKey(key_name);

    // Create, then reopen with explicit backend.
    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, default_backend);
    ASSERT_NE(nullptr, key);
    key.reset();

    auto opened = mpss::KeyPair::Open(key_name, default_backend);
    ASSERT_NE(nullptr, opened);
    EXPECT_STREQ(default_backend, opened->backend_name());
    opened->delete_key();
}

TEST(BackendTest, CreateKeyWithInvalidBackend)
{
    auto key = mpss::KeyPair::Create(test_key_name("test_bad_backend"), ecdsa_secp256r1_sha256, "nonexistent");
    EXPECT_EQ(nullptr, key);
}

TEST(BackendTest, OpenKeyWithInvalidBackend)
{
    auto key = mpss::KeyPair::Open(test_key_name("test_bad_backend"), "nonexistent");
    EXPECT_EQ(nullptr, key);
}

TEST(BackendTest, VerifyWithExplicitBackend)
{
    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_verify_explicit");
    MPSS::DeleteKey(key_name);

    // Create and sign with a key.
    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, default_backend);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('a'));
    const std::size_t sig_size = key->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = key->sign_hash(hash, signature);
    ASSERT_GT(written, std::size_t{0});
    signature.resize(written);

    // Extract the public key.
    const std::size_t vk_size = key->extract_key({});
    std::vector<std::byte> vk(vk_size);
    const std::size_t read = key->extract_key(vk);
    ASSERT_EQ(vk_size, read);

    key->delete_key();

    // Verify using the explicit backend overload.
    const bool verified = mpss::verify(hash, vk, ecdsa_secp256r1_sha256, signature, default_backend);
    EXPECT_TRUE(verified);
}

TEST(BackendTest, VerifyWithInvalidBackend)
{
    std::vector<std::byte> dummy(32, static_cast<std::byte>('x'));
    const bool result = mpss::verify(dummy, dummy, ecdsa_secp256r1_sha256, dummy, "nonexistent");
    EXPECT_FALSE(result);
}

// --- KeyPolicy tests ---

TEST(KeyPolicyTest, NoneIsZero)
{
    static_assert(KeyPolicy::none == KeyPolicy{0});
    static_assert(static_cast<std::uint64_t>(KeyPolicy::none) == 0);
}

TEST(KeyPolicyTest, SizeIs64Bits)
{
    static_assert(sizeof(KeyPolicy) == sizeof(std::uint64_t));
}

TEST(KeyPolicyTest, OrWithNoneIsIdentity)
{
    static_assert((KeyPolicy::none | KeyPolicy::none) == KeyPolicy::none); // NOLINT(misc-redundant-expression)
}

TEST(KeyPolicyTest, AndWithNoneIsNone)
{
    static_assert((KeyPolicy::none & KeyPolicy::none) == KeyPolicy::none); // NOLINT(misc-redundant-expression)
}

TEST(KeyPolicyTest, RoundTripThroughUint64)
{
    // Exercises the C API cast path.
    constexpr auto policy = KeyPolicy{0xDEAD'BEEF'CAFE'1234ULL};
    constexpr auto raw = static_cast<std::uint64_t>(policy);
    constexpr auto back = static_cast<KeyPolicy>(raw);
    static_assert(back == policy);
}

TEST(KeyPolicyTest, YubikeyPinFieldValues)
{
    static_assert(static_cast<std::uint64_t>(KeyPolicy::yubikey_pin_never) == 1);
    static_assert(static_cast<std::uint64_t>(KeyPolicy::yubikey_pin_once) == 2);
    static_assert(static_cast<std::uint64_t>(KeyPolicy::yubikey_pin_always) == 3);
}

TEST(KeyPolicyTest, YubikeyTouchFieldValues)
{
    static_assert(static_cast<std::uint64_t>(KeyPolicy::yubikey_touch_never) == (1U << 4U));
    static_assert(static_cast<std::uint64_t>(KeyPolicy::yubikey_touch_always) == (2U << 4U));
    static_assert(static_cast<std::uint64_t>(KeyPolicy::yubikey_touch_cached) == (3U << 4U));
}

TEST(KeyPolicyTest, PinMaskExtractsPinOnly)
{
    constexpr auto combined = KeyPolicy::yubikey_pin_once | KeyPolicy::yubikey_touch_cached;
    static_assert((combined & yubikey_pin_mask) == KeyPolicy::yubikey_pin_once);
}

TEST(KeyPolicyTest, TouchMaskExtractsTouchOnly)
{
    constexpr auto combined = KeyPolicy::yubikey_pin_once | KeyPolicy::yubikey_touch_cached;
    static_assert((combined & yubikey_touch_mask) == KeyPolicy::yubikey_touch_cached);
}

TEST(KeyPolicyTest, FieldsDoNotInterfere)
{
    // Setting PIN policy does not affect touch field and vice versa.
    constexpr auto pin_only = KeyPolicy::yubikey_pin_always;
    static_assert((pin_only & yubikey_touch_mask) == KeyPolicy::none);

    constexpr auto touch_only = KeyPolicy::yubikey_touch_always;
    static_assert((touch_only & yubikey_pin_mask) == KeyPolicy::none);
}

TEST(KeyPolicyTest, CombineAndExtractAllFields)
{
    constexpr auto combined = KeyPolicy::yubikey_pin_always | KeyPolicy::yubikey_touch_cached;
    constexpr auto pin = static_cast<std::uint64_t>(combined & yubikey_pin_mask);
    constexpr auto touch = static_cast<std::uint64_t>(combined & yubikey_touch_mask) >> 4;
    static_assert(3 == pin);
    static_assert(3 == touch);
}

#ifdef MPSS_BACKEND_YUBIKEY
TEST_F(MPSS, YubiKeyBackendRejectsUnsupportedKeyPolicy)
{
    const std::string key_name = test_key_name("mpss_yubikey_unsupported_policy_test");
    DeleteKey(key_name);
    EXPECT_EQ(nullptr, mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey",
                                             KeyPolicy::apple_secure_enclave_user_presence));
    EXPECT_NE(std::string::npos, mpss::get_error().find("does not support the requested key policy"));
    EXPECT_EQ(nullptr, mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey", static_cast<KeyPolicy>(4U)));
    EXPECT_NE(std::string::npos, mpss::get_error().find("does not support the requested key policy"));
    EXPECT_EQ(nullptr,
              mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey", static_cast<KeyPolicy>(4U << 4U)));
    EXPECT_NE(std::string::npos, mpss::get_error().find("does not support the requested key policy"));
}
#endif

TEST(KeyPolicyTest, CreateKeyWithPolicyNone)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name("test_key_policy_none");
    MPSS::DeleteKey(key_name);

    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, KeyPolicy::none);
    ASSERT_NE(nullptr, key);

    // Verify the key works.
    const std::vector<std::byte> hash(32, static_cast<std::byte>('p'));
    const std::size_t sig_size = key->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = key->sign_hash(hash, signature);
    ASSERT_GT(written, std::size_t{0});
    signature.resize(written);
    EXPECT_TRUE(key->verify(hash, signature));

    key->delete_key();
}

// --- hex_string_to_bytes tests ---

TEST(HexStringToBytesTest, ValidEvenLengthRoundTrips)
{
    auto result = mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("deadBEEF");
    ASSERT_TRUE(result.has_value());
    const std::vector<std::byte> expected{static_cast<std::byte>(0xde), static_cast<std::byte>(0xad),
                                          static_cast<std::byte>(0xbe), static_cast<std::byte>(0xef)};
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - guarded by the assertion above.
    EXPECT_EQ(expected, result.value());
}

TEST(HexStringToBytesTest, EmptyStringIsEmptyVector)
{
    auto result = mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("");
    ASSERT_TRUE(result.has_value());
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - guarded by the assertion above.
    EXPECT_TRUE(result.value().empty());
}

TEST(HexStringToBytesTest, OddLengthRejected)
{
    EXPECT_FALSE(mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("abc").has_value());
}

TEST(HexStringToBytesTest, PartialWindowRejected)
{
    // "1g": from_chars would parse '1' as 0x01 and stop at 'g'. Without the end-pointer check this
    // window is silently accepted; it must be rejected instead.
    EXPECT_FALSE(mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("1g").has_value());
}

TEST(HexStringToBytesTest, LeadingNonHexRejected)
{
    EXPECT_FALSE(mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("g1").has_value());
}

TEST(HexStringToBytesTest, EmbeddedPrefixRejected)
{
    // "0x12": the "0x" window parses '0' and stops at 'x'; it must be rejected, not read as 0x00.
    EXPECT_FALSE(mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("0x12").has_value());
}

TEST(HexStringToBytesTest, InvalidCharInLaterWindowRejected)
{
    // A valid first byte followed by a partial window must still be rejected.
    EXPECT_FALSE(mpss::utils::hex_string_to_bytes<std::vector<std::byte>>("ab1g").has_value());
}

// --- Key name length limit tests ---

TEST(KeyNameLimitTest, KeyNameTooLongCreate)
{
    const std::string long_name(65, 'x');
    auto key = mpss::KeyPair::Create(long_name, ecdsa_secp256r1_sha256);
    EXPECT_EQ(nullptr, key);
}

TEST(KeyNameLimitTest, KeyNameTooLongOpen)
{
    const std::string long_name(65, 'x');
    auto key = mpss::KeyPair::Open(long_name);
    EXPECT_EQ(nullptr, key);
}

TEST_F(MPSS, KeyNameMaxLength)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = test_key_name_of_length(64);
    MPSS::DeleteKey(key_name);

    auto handle = MPSS::CreateKey(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle);

    handle->delete_key();
}

TEST_F(MPSS, KeyNameMaxLengthDistinguished)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    // Two names at the maximum length that differ only in the last character.
    // If the backend silently truncates, these would collide.
    std::string name_a = test_key_name_of_length(64);
    std::string name_b = test_key_name_of_length(64);
    name_a.back() = 'a';
    name_b.back() = 'b';

    MPSS::DeleteKey(name_a);
    MPSS::DeleteKey(name_b);

    auto handle_a = MPSS::CreateKey(name_a, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle_a);

    auto handle_b = MPSS::CreateKey(name_b, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle_b);

    // Sign with key A.
    const std::vector<std::byte> hash(32, static_cast<std::byte>('z'));
    const std::size_t sig_size = handle_a->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = handle_a->sign_hash(hash, signature);
    ASSERT_GT(written, std::size_t{0});
    signature.resize(written);

    // Verify with key A succeeds.
    EXPECT_TRUE(handle_a->verify(hash, signature));

    // Verify with key B fails - these are distinct keys.
    EXPECT_FALSE(handle_b->verify(hash, signature));

    handle_a->delete_key();
    handle_b->delete_key();
}

class CrossBackendTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Check that both 'os' and 'yubikey' backends are available before running cross-backend tests.
        const auto backends = mpss::get_available_backends();
        bool has_os = false;
        bool has_yubikey = false;
        for (const char *name : backends)
        {
            if (0 == std::strcmp("os", name))
            {
                has_os = true;
            }
            if (0 == std::strcmp("yubikey", name))
            {
                has_yubikey = true;
            }
        }
        if (!has_os || !has_yubikey)
        {
            GTEST_SKIP() << "Cross-backend tests require both 'os' and 'yubikey' backends.";
        }
    }
};

TEST_F(CrossBackendTest, SignOnOneBackendVerifyOnAnother)
{
    // Create and sign with the OS backend.
    const std::string key_name = test_key_name("test_cross_backend_sign");
    MPSS::DeleteKey(key_name);

    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "os");
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('c'));
    const std::size_t sig_size = key->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = key->sign_hash(hash, signature);
    ASSERT_GT(written, std::size_t{0});
    signature.resize(written);

    // Extract the public key.
    const std::size_t vk_size = key->extract_key({});
    std::vector<std::byte> vk(vk_size);
    const std::size_t read = key->extract_key(vk);
    ASSERT_EQ(vk_size, read);

    key->delete_key();

    // Verify with the YubiKey backend (standalone verification uses software ECDSA).
    const bool verified = mpss::verify(hash, vk, ecdsa_secp256r1_sha256, signature, "yubikey");
    EXPECT_TRUE(verified);
}

TEST_F(CrossBackendTest, CreateKeyOnEachBackend)
{
    const std::string os_key_name = test_key_name("test_cross_os_key");
    const std::string yk_key_name = test_key_name("test_cross_yk_key");

    MPSS::DeleteKey(os_key_name);
    MPSS::DeleteKey(yk_key_name);

    // Create a key on the OS backend.
    auto os_key = mpss::KeyPair::Create(os_key_name, ecdsa_secp256r1_sha256, "os");
    ASSERT_NE(nullptr, os_key);

    // Create a key on the YubiKey backend. The backend may be registered without
    // any device being currently available, so treat creation failure as a skip.
    // touch=never so signing does not block on a physical touch during automated runs; pin=once
    // uses the configured PIN (MPSS_YUBIKEY_PIN) for the signing operation.
    auto yk_key = mpss::KeyPair::Create(yk_key_name, ecdsa_secp256r1_sha256, "yubikey",
                                        KeyPolicy::yubikey_touch_never | KeyPolicy::yubikey_pin_once);
    if (nullptr == yk_key)
    {
        os_key->delete_key();
        GTEST_SKIP() << "YubiKey backend registered but no device available.";
    }

    // Both should be able to sign independently.
    const std::vector<std::byte> hash(32, static_cast<std::byte>('d'));

    const std::size_t os_sig_size = os_key->sign_hash(hash, {});
    std::vector<std::byte> os_sig(os_sig_size);
    const std::size_t os_written = os_key->sign_hash(hash, os_sig);
    EXPECT_GT(os_written, std::size_t{0});

    const std::size_t yk_sig_size = yk_key->sign_hash(hash, {});
    std::vector<std::byte> yk_sig(yk_sig_size);
    const std::size_t yk_written = yk_key->sign_hash(hash, yk_sig);
    EXPECT_GT(yk_written, std::size_t{0});

    os_key->delete_key();
    yk_key->delete_key();
}

#ifdef MPSS_BACKEND_YUBIKEY

#ifndef MPSS_CORE_IS_SHARED
// Env-driven pin/touch policy resolution. Device-independent: exercises the pure resolver logic
// (resolve_pin_policy / resolve_touch_policy) with the policy environment variables, no hardware.
class YubiKeyPolicyEnv : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        save("MPSS_YUBIKEY_PINPOLICY", saved_pin_);
        save("MPSS_YUBIKEY_TOUCHPOLICY", saved_touch_);
        save("MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE", saved_allow_);
    }

    void TearDown() override
    {
        restore("MPSS_YUBIKEY_PINPOLICY", saved_pin_);
        restore("MPSS_YUBIKEY_TOUCHPOLICY", saved_touch_);
        restore("MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE", saved_allow_);
    }

    static void save(const char *name, std::optional<std::string> &slot)
    {
        const char *value = std::getenv(name); // NOLINT(concurrency-mt-unsafe)
        slot = (nullptr == value) ? std::nullopt : std::optional<std::string>{value};
    }

    static void restore(const char *name, const std::optional<std::string> &slot)
    {
        if (slot.has_value())
        {
            setenv(name, slot->c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            unsetenv(name); // NOLINT(concurrency-mt-unsafe)
        }
    }

    std::optional<std::string> saved_pin_;
    std::optional<std::string> saved_touch_;
    std::optional<std::string> saved_allow_;
};

TEST_F(YubiKeyPolicyEnv, EnvNeverGatedBehindOptIn)
{
    namespace yku = mpss::impl::yubikey::utils;

    // Oracles: the programmatic mappings the env path should resolve to (env-independent).
    const std::uint8_t pin_once = yku::resolve_pin_policy(KeyPolicy::yubikey_pin_once);
    const std::uint8_t pin_never = yku::resolve_pin_policy(KeyPolicy::yubikey_pin_never);
    const std::uint8_t touch_cached = yku::resolve_touch_policy(KeyPolicy::yubikey_touch_cached);
    const std::uint8_t touch_never = yku::resolve_touch_policy(KeyPolicy::yubikey_touch_never);
    ASSERT_NE(pin_once, pin_never);
    ASSERT_NE(touch_cached, touch_never);

    setenv("MPSS_YUBIKEY_PINPOLICY", "never", 1);   // NOLINT(concurrency-mt-unsafe)
    setenv("MPSS_YUBIKEY_TOUCHPOLICY", "never", 1); // NOLINT(concurrency-mt-unsafe)

    // Without the opt-in flag, env 'never' is refused and the safe default is used.
    unsetenv("MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE"); // NOLINT(concurrency-mt-unsafe)
    EXPECT_EQ(pin_once, yku::resolve_pin_policy(KeyPolicy::none));
    EXPECT_EQ(touch_cached, yku::resolve_touch_policy(KeyPolicy::none));

    // A non-affirmative flag value likewise does not enable the downgrade.
    setenv("MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE", "0", 1); // NOLINT(concurrency-mt-unsafe)
    EXPECT_EQ(pin_once, yku::resolve_pin_policy(KeyPolicy::none));
    EXPECT_EQ(touch_cached, yku::resolve_touch_policy(KeyPolicy::none));

    // With the opt-in flag, env 'never' is honored.
    setenv("MPSS_YUBIKEY_ALLOW_POLICY_DOWNGRADE", "1", 1); // NOLINT(concurrency-mt-unsafe)
    EXPECT_EQ(pin_never, yku::resolve_pin_policy(KeyPolicy::none));
    EXPECT_EQ(touch_never, yku::resolve_touch_policy(KeyPolicy::none));

    // The programmatic path is unaffected by the gate (explicit caller choice, no env consulted).
    EXPECT_EQ(pin_never, yku::resolve_pin_policy(KeyPolicy::yubikey_pin_never));
    EXPECT_EQ(touch_never, yku::resolve_touch_policy(KeyPolicy::yubikey_touch_never));
}

TEST(YubiKeyPolicyEnvTest, AffirmativeEnvironmentValues)
{
    namespace yku = mpss::impl::yubikey::utils;

    EXPECT_TRUE(yku::is_affirmative_environment_value("1"));
    EXPECT_TRUE(yku::is_affirmative_environment_value("true"));
    EXPECT_TRUE(yku::is_affirmative_environment_value("TRUE"));
    EXPECT_TRUE(yku::is_affirmative_environment_value("yes"));
    EXPECT_TRUE(yku::is_affirmative_environment_value("On"));
    EXPECT_FALSE(yku::is_affirmative_environment_value(""));
    EXPECT_FALSE(yku::is_affirmative_environment_value("0"));
    EXPECT_FALSE(yku::is_affirmative_environment_value("false"));
    EXPECT_FALSE(yku::is_affirmative_environment_value("no"));
}

// Env-driven management-key authentication. Requires a connected YubiKey: exercises the live
// authenticate_mgm_key() path. A freshly connected session has no verified PIN, so the
// PIN-protected branch always fails first and control reaches the env-key branch regardless of the
// device's management-key mode.
class YubiKeyMgmKeyEnv : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const char *value = std::getenv("MPSS_YUBIKEY_MGM_KEY"); // NOLINT(concurrency-mt-unsafe)
        saved_mgm_ = (nullptr == value) ? std::nullopt : std::optional<std::string>{value};
        value = std::getenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY"); // NOLINT(concurrency-mt-unsafe)
        saved_allow_default_ = (nullptr == value) ? std::nullopt : std::optional<std::string>{value};
        unsetenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY"); // NOLINT(concurrency-mt-unsafe)

        serials_ = mpss::impl::yubikey::YubiKeyPIV::available_serials().value_or(std::vector<std::uint32_t>{});
        if (serials_.empty())
        {
            GTEST_SKIP() << "Requires a connected YubiKey.";
        }
    }

    void TearDown() override
    {
        if (saved_mgm_.has_value())
        {
            setenv("MPSS_YUBIKEY_MGM_KEY", saved_mgm_->c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            unsetenv("MPSS_YUBIKEY_MGM_KEY"); // NOLINT(concurrency-mt-unsafe)
        }
        if (saved_allow_default_.has_value())
        {
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            setenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY", saved_allow_default_->c_str(), 1);
        }
        else
        {
            unsetenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY"); // NOLINT(concurrency-mt-unsafe)
        }
    }

    std::vector<std::uint32_t> serials_;
    std::optional<std::string> saved_mgm_;
    std::optional<std::string> saved_allow_default_;
};

TEST_F(YubiKeyMgmKeyEnv, SuppliedKeyMustAuthenticateNoDefaultFallback)
{
    mpss::impl::yubikey::YubiKeyPIV piv{serials_[0]};
    ASSERT_TRUE(piv.is_connected());

    // A valid-length management key that does not match the device must fail; MPSS must not fall
    // back to the factory-default key.
    setenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY", "1", 1); // NOLINT(concurrency-mt-unsafe)
    const std::string wrong_key(48, 'a');
    setenv("MPSS_YUBIKEY_MGM_KEY", wrong_key.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
    EXPECT_FALSE(piv.authenticate_mgm_key());

    // A set-but-malformed value is likewise a hard error, not a default fallback.
    setenv("MPSS_YUBIKEY_MGM_KEY", "not-hex", 1); // NOLINT(concurrency-mt-unsafe)
    EXPECT_FALSE(piv.authenticate_mgm_key());
}

TEST_F(YubiKeyMgmKeyEnv, FactoryDefaultRequiresExplicitOptIn)
{
    mpss::impl::yubikey::YubiKeyPIV piv{serials_[0]};
    ASSERT_TRUE(piv.is_connected());

    unsetenv("MPSS_YUBIKEY_MGM_KEY"); // NOLINT(concurrency-mt-unsafe)
    EXPECT_FALSE(piv.authenticate_mgm_key());

    setenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY", "0", 1); // NOLINT(concurrency-mt-unsafe)
    EXPECT_FALSE(piv.authenticate_mgm_key());
}

TEST_F(YubiKeyMgmKeyEnv, FactoryDefaultWorksWithExplicitOptIn)
{
    mpss::impl::yubikey::YubiKeyPIV piv{serials_[0]};
    ASSERT_TRUE(piv.is_connected());

    unsetenv("MPSS_YUBIKEY_MGM_KEY");                     // NOLINT(concurrency-mt-unsafe)
    setenv("MPSS_YUBIKEY_ALLOW_DEFAULT_MGM_KEY", "1", 1); // NOLINT(concurrency-mt-unsafe)
    if (!piv.authenticate_mgm_key())
    {
        GTEST_SKIP() << "Connected YubiKey does not use the factory-default management key.";
    }
}

// Slot-binding tests create a key through the public API, which selects a device on its own, but
// then inspect and repair that device directly through YubiKeyPIV. Pinning MPSS_YUBIKEY_SERIAL
// keeps both halves on the same device when more than one YubiKey is attached.
class YubiKeySlotBinding : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const char *value = std::getenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        saved_serial_ = (nullptr == value) ? std::nullopt : std::optional<std::string>{value};

        serials_ = mpss::impl::yubikey::YubiKeyPIV::available_serials().value_or(std::vector<std::uint32_t>{});
        if (serials_.empty())
        {
            GTEST_SKIP() << "Requires a connected YubiKey.";
        }

        const std::string target = std::to_string(serials_[0]);
        setenv("MPSS_YUBIKEY_SERIAL", target.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
    }

    void TearDown() override
    {
        if (saved_serial_.has_value())
        {
            setenv("MPSS_YUBIKEY_SERIAL", saved_serial_->c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        }
    }

    std::vector<std::uint32_t> serials_;
    std::optional<std::string> saved_serial_;
};

// A slot label describes the key held in that slot. Replacing the key without rewriting the label
// leaves a slot whose name no longer matches its contents, and that name must not resolve.
TEST_F(YubiKeySlotBinding, LabelDoesNotResolveAfterSlotKeyIsReplaced)
{
    using mpss::impl::KeyProbeStatus;
    using mpss::impl::yubikey::YubiKeyPIV;

    const std::string key_name = test_key_name("mpss_yk_slot_binding_test");
    MPSS::DeleteKey(key_name);

    if (nullptr == mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey"))
    {
        GTEST_SKIP() << "Connected YubiKey cannot create keys in its current state.";
    }

    std::uint8_t slot = 0;
    {
        YubiKeyPIV piv{serials_[0]};
        ASSERT_TRUE(piv.is_connected());

        const auto located = piv.find_slot_by_name(key_name);
        ASSERT_EQ(KeyProbeStatus::found, located.status);
        slot = located.value.slot;

        // Replace the key material while leaving the label in place.
        ASSERT_EQ(mpss::impl::yubikey::YubiKeyPIV::GenerateResult::generated,
                  piv.generate_key(slot, mpss::impl::yubikey::utils::mpss_to_yk_algorithm(ecdsa_secp256r1_sha256)));
    }

    const bool opened = (nullptr != mpss::KeyPair::Open(key_name, "yubikey"));

    // The slot now holds a key its label does not describe, so MPSS can neither open it by name nor
    // offer it for reuse. Reclaim it before asserting, so a failed expectation cannot strand it.
    {
        YubiKeyPIV piv{serials_[0]};
        EXPECT_TRUE(piv.is_connected());
        EXPECT_EQ(mpss::impl::yubikey::YubiKeyPIV::DeleteResult::deleted, piv.delete_key(slot));
    }

    EXPECT_FALSE(opened);
}

TEST_F(YubiKeySlotBinding, ReferenceDisambiguatesOnlySlotsWithTheRequestedName)
{
    using mpss::impl::KeyProbeStatus;
    using mpss::impl::yubikey::YubiKeyPIV;

    const KeyLocation first{"yubikey", test_key_name("duplicate_label_a"), std::to_string(serials_[0])};
    const KeyLocation second{"yubikey", test_key_name("duplicate_label_b"), first.device_id};
    auto key_a = KeyPair::Create(first, ecdsa_secp256r1_sha256);
    if (nullptr == key_a)
    {
        GTEST_SKIP() << "Connected YubiKey cannot create keys in its current state.";
    }
    SCOPE_GUARD(static_cast<void>(key_a->delete_key()));
    auto key_b = KeyPair::Create(second, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key_b) << mpss::get_error();
    SCOPE_GUARD(static_cast<void>(key_b->delete_key()));

    KeyReference reference_a{key_a->location(), key_a->algorithm(), std::vector<std::byte>(key_a->extract_key_size())};
    KeyReference reference_b{key_b->location(), key_b->algorithm(), std::vector<std::byte>(key_b->extract_key_size())};
    ASSERT_EQ(reference_a.public_key.size(), key_a->extract_key(reference_a.public_key));
    ASSERT_EQ(reference_b.public_key.size(), key_b->extract_key(reference_b.public_key));
    ASSERT_NE(reference_a.public_key, reference_b.public_key);

    reference_b.location.name = first.name;
    EXPECT_EQ(nullptr, KeyPair::Open(reference_b));
    EXPECT_TRUE(mpss::has_error());

    {
        YubiKeyPIV piv{serials_[0]};
        ASSERT_TRUE(piv.is_connected());
        const auto slot_a = piv.find_slot_by_name(first.name);
        const auto slot_b = piv.find_slot_by_name(second.name);
        ASSERT_EQ(KeyProbeStatus::found, slot_a.status);
        ASSERT_EQ(KeyProbeStatus::found, slot_b.status);

        if (!piv.authenticate_mgm_key())
        {
            ASSERT_TRUE(mpss::impl::yubikey::authenticate_pin_interactive(piv, "label test key"));
            ASSERT_TRUE(piv.authenticate_mgm_key()) << mpss::get_error();
        }
        ASSERT_TRUE(piv.write_slot_label(slot_b.value.slot, first.name)) << mpss::get_error();

        EXPECT_EQ(KeyProbeStatus::operational_error, piv.find_slot_by_name(first.name).status);
        EXPECT_NE(std::string::npos, mpss::get_error().find("slots share this name"));
        const auto matching_a = piv.find_slot_by_name(first.name, reference_a.public_key);
        const auto matching_b = piv.find_slot_by_name(first.name, reference_b.public_key);
        ASSERT_EQ(KeyProbeStatus::found, matching_a.status);
        ASSERT_EQ(KeyProbeStatus::found, matching_b.status);
        EXPECT_EQ(slot_a.value.slot, matching_a.value.slot);
        EXPECT_EQ(slot_b.value.slot, matching_b.value.slot);
        EXPECT_EQ(KeyProbeStatus::not_found, piv.find_slot_by_name(second.name, reference_b.public_key).status);
    }

    EXPECT_EQ(nullptr, KeyPair::Open(first));
    EXPECT_NE(std::string::npos, mpss::get_error().find("slots share this name"));
    auto opened_a = KeyPair::Open(reference_a);
    ASSERT_NE(nullptr, opened_a) << mpss::get_error();
    auto opened_b = KeyPair::Open(reference_b);
    ASSERT_NE(nullptr, opened_b) << mpss::get_error();

    std::vector<std::byte> public_key(reference_a.public_key.size());
    ASSERT_EQ(public_key.size(), opened_a->extract_key(public_key));
    EXPECT_EQ(reference_a.public_key, public_key);
    ASSERT_EQ(public_key.size(), opened_b->extract_key(public_key));
    EXPECT_EQ(reference_b.public_key, public_key);
}

// A scan cannot run from a thread that already holds a connection, since connecting to each reader
// in turn would disturb the session that thread established. The refusal must report that nothing
// was established about any device, which is not the same answer as no device being attached.
TEST_F(YubiKeySlotBinding, AScanThatCannotRunIsNotAnEmptyDeviceList)
{
    using mpss::impl::yubikey::YubiKeyPIV;

    // Established first, so the contrast is against this same device on this same host.
    const auto reachable = YubiKeyPIV::available_serials();
    ASSERT_TRUE(reachable.has_value());
    ASSERT_FALSE(reachable->empty());

    {
        YubiKeyPIV piv{serials_[0]};
        ASSERT_TRUE(piv.is_connected());
        {
            YubiKeyPIV nested{serials_[0]};
            EXPECT_FALSE(nested.is_connected());
        }
        const std::optional<std::vector<std::uint32_t>> unlistable = YubiKeyPIV::available_serials();
        EXPECT_FALSE(unlistable.has_value());
        EXPECT_NE(std::optional<std::vector<std::uint32_t>>{std::vector<std::uint32_t>{}}, unlistable);
    }
    EXPECT_TRUE(YubiKeyPIV::available_serials().has_value());
}

TEST_F(YubiKeySlotBinding, ExplicitLocationsOverrideEnvironmentAndReportActualSerial)
{
    std::uint32_t absent_serial = 0xFFFFFFFF;
    while (std::ranges::find(serials_, absent_serial) != serials_.end())
    {
        --absent_serial;
    }
    const auto absent_id = std::to_string(absent_serial);
    setenv("MPSS_YUBIKEY_SERIAL", absent_id.c_str(), 1); // NOLINT(concurrency-mt-unsafe)

    const auto actual_id = std::to_string(serials_[0]);
    const KeyLocation requested{"yubikey", test_key_name("explicit_location"), "000" + actual_id};
    auto created = KeyPair::Create(requested, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, created) << mpss::get_error();
    bool deleted = false;
    SCOPE_GUARD({
        if (!deleted)
        {
            static_cast<void>(created->delete_key());
        }
    });
    const auto actual = created->location();
    EXPECT_EQ(std::optional<std::string>{actual_id}, actual.device_id);

    const auto devices = mpss::get_available_devices("yubikey");
    ASSERT_TRUE(devices.has_value());
    EXPECT_NE(devices->end(), std::ranges::find(*devices, actual_id));
    EXPECT_NE(nullptr, KeyPair::Open(actual));
    EXPECT_EQ(nullptr, KeyPair::Create(actual.name, ecdsa_secp256r1_sha256, "yubikey"));
    EXPECT_NE(std::string::npos, mpss::get_error().find(absent_id));
    EXPECT_EQ(nullptr, KeyPair::Open(actual.name, "yubikey"));
    EXPECT_NE(std::string::npos, mpss::get_error().find(absent_id));
    EXPECT_FALSE(KeyPair::Delete(actual.name, "yubikey"));
    EXPECT_NE(std::string::npos, mpss::get_error().find(absent_id));

    const KeyLocation automatic{"yubikey", actual.name, std::nullopt};
    if (1 == serials_.size())
    {
        auto opened = KeyPair::Open(automatic);
        ASSERT_NE(nullptr, opened) << mpss::get_error();
        EXPECT_EQ(actual.device_id, opened->location().device_id);
    }
    else
    {
        EXPECT_EQ(nullptr, KeyPair::Open(automatic));
        EXPECT_NE(std::string::npos, mpss::get_error().find("Multiple YubiKeys"));
    }

    const KeyLocation missing{"yubikey", actual.name, absent_id};
    EXPECT_EQ(nullptr, KeyPair::Create(missing, ecdsa_secp256r1_sha256));
    EXPECT_EQ(nullptr, KeyPair::Open(missing));
    EXPECT_FALSE(KeyPair::Delete(missing));
    EXPECT_NE(nullptr, KeyPair::Open(actual));

    ASSERT_EQ(0, setenv("MPSS_YUBIKEY_SERIAL", actual_id.c_str(), 1)); // NOLINT(concurrency-mt-unsafe)
    EXPECT_EQ(nullptr, KeyPair::Create(actual.name, ecdsa_secp256r1_sha256, "yubikey"));
    EXPECT_NE(std::string::npos, mpss::get_error().find("already exists"));
    auto opened = KeyPair::Open(actual.name, "yubikey");
    ASSERT_NE(nullptr, opened) << mpss::get_error();
    EXPECT_EQ(actual.device_id, opened->location().device_id);
    deleted = KeyPair::Delete(actual.name, "yubikey");
    EXPECT_TRUE(deleted) << mpss::get_error();
}

#endif

// The sentinel name used to mark free/deleted slots is reserved and must not be accepted as a user key
// name. The reject happens before any device access, so the test needs no connected YubiKey.
TEST(YubiKeyReservedName, MarkerNameRejected)
{
#ifndef MPSS_CORE_IS_SHARED
    EXPECT_TRUE(mpss::impl::yubikey::is_reserved_key_name("(available)"));
    EXPECT_FALSE(mpss::impl::yubikey::is_reserved_key_name("my-key"));
#endif

    EXPECT_EQ(nullptr, mpss::KeyPair::Create("(available)", ecdsa_secp256r1_sha256, "yubikey"));
    EXPECT_EQ(nullptr, mpss::KeyPair::Open("(available)", "yubikey"));
}

TEST(KeyLocationTest, YubiKeyRejectsInvalidSerialBeforeDeviceAccess)
{
    for (const auto *id : {"", "0", "-1", "+1", " 1", "1 ", "1x", "4294967296"})
    {
        const KeyLocation location{"yubikey", "invalid_device", id};
        EXPECT_EQ(nullptr, KeyPair::Create(location, ecdsa_secp256r1_sha256)) << id;
        EXPECT_TRUE(mpss::has_error());
        EXPECT_EQ(nullptr, KeyPair::Open(location)) << id;
        EXPECT_TRUE(mpss::has_error());
        EXPECT_FALSE(KeyPair::Delete(location)) << id;
        EXPECT_TRUE(mpss::has_error());
    }
}

// Multi-device YubiKey tests. These tests require at least two YubiKeys to be physically connected.
// They are automatically skipped when fewer than two devices are available.

class MultiYubiKeyTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        serials_ = mpss::impl::yubikey::YubiKeyPIV::available_serials().value_or(std::vector<std::uint32_t>{});

        // Read the pin before the skip below. GTEST_SKIP returns from SetUp but TearDown still
        // runs, so a value saved after it would be missed and the restore would clear a variable
        // this fixture never read.
        const char *existing = std::getenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        if (nullptr != existing)
        {
            saved_serial_env_ = existing;
        }

        if (serials_.size() < 2)
        {
            GTEST_SKIP() << "Multi-device tests require at least two YubiKeys.";
        }
    }

    void TearDown() override
    {
        // Restore original env var state.
        if (saved_serial_env_.empty())
        {
            unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            setenv("MPSS_YUBIKEY_SERIAL", saved_serial_env_.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
    }

    void TargetDevice(std::uint32_t serial)
    {
        const std::string serial_str = std::to_string(serial);
        setenv("MPSS_YUBIKEY_SERIAL", serial_str.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
    }

    void ClearDeviceTarget()
    {
        unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
    }

    std::vector<std::uint32_t> serials_;
    std::string saved_serial_env_;
};

TEST_F(MultiYubiKeyTest, OpenKeyFindsKeyOnNonFirstDevice)
{
    // Create a key on the second YubiKey (the one that would NOT be found by the old first-available logic).
    TargetDevice(serials_[1]);

    const std::string key_name = test_key_name("test_multi_yk_open");

    // Clean up any leftover from a previous run.
    auto leftover = mpss::KeyPair::Open(key_name, "yubikey");
    if (nullptr != leftover)
    {
        leftover->delete_key();
        leftover.reset();
    }

    auto key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey");
    ASSERT_NE(nullptr, key);
    key.reset();

    // Open should find the key on the second YubiKey when the serial is specified.
    auto opened = mpss::KeyPair::Open(key_name, "yubikey");
    ASSERT_NE(nullptr, opened);

    // Sign and verify to confirm the correct device is being used for operations.
    const std::vector<std::byte> hash(32, static_cast<std::byte>('m'));
    const std::size_t sig_size = opened->sign_hash(hash, {});
    std::vector<std::byte> signature(sig_size);
    const std::size_t written = opened->sign_hash(hash, signature);
    ASSERT_GT(written, std::size_t{0});
    signature.resize(written);

    EXPECT_TRUE(opened->verify(hash, signature));

    // Clean up. The opened handle has the correct serial stored, so delete_key targets the right device.
    opened->delete_key();
}

TEST_F(MultiYubiKeyTest, SameNameUsesIndependentLocationsWithoutEnvironmentSwitching)
{
    const auto name = test_key_name("two_device_locations");
    const KeyLocation first{"yubikey", name, std::to_string(serials_[0])};
    const KeyLocation second{"yubikey", name, std::to_string(serials_[1])};
    auto key_a = KeyPair::Create(first, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key_a) << mpss::get_error();
    bool first_deleted = false;
    SCOPE_GUARD({
        if (!first_deleted)
        {
            static_cast<void>(key_a->delete_key());
        }
    });
    auto key_b = KeyPair::Create(second, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key_b) << mpss::get_error();
    SCOPE_GUARD(static_cast<void>(key_b->delete_key()));

    KeyReference reference_a{key_a->location(), key_a->algorithm(), std::vector<std::byte>(key_a->extract_key_size())};
    KeyReference reference_b{key_b->location(), key_b->algorithm(), std::vector<std::byte>(key_b->extract_key_size())};
    ASSERT_EQ(reference_a.public_key.size(), key_a->extract_key(reference_a.public_key));
    ASSERT_EQ(reference_b.public_key.size(), key_b->extract_key(reference_b.public_key));
    EXPECT_NE(reference_a.public_key, reference_b.public_key);
    auto bound_a = KeyPair::Open(reference_a);
    auto bound_b = KeyPair::Open(reference_b);
    ASSERT_NE(nullptr, bound_a) << mpss::get_error();
    ASSERT_NE(nullptr, bound_b) << mpss::get_error();

    const std::vector<std::byte> hash(32, std::byte{0x32});
    std::array<std::vector<std::byte>, 2> signatures{std::vector<std::byte>(bound_a->sign_hash_size()),
                                                     std::vector<std::byte>(bound_b->sign_hash_size())};
    std::array<std::size_t, 2> written{};
    std::array<std::string, 2> errors;
    const auto sign = [&](std::size_t index) {
        const auto &key = (0 == index) ? bound_a : bound_b;
        written[index] = key->sign_hash(hash, signatures[index]);
        errors[index] = mpss::get_error();
    };
    std::jthread thread_a(sign, std::size_t{0});
    std::jthread thread_b(sign, std::size_t{1});
    thread_a.join();
    thread_b.join();
    for (std::size_t index = 0; index < written.size(); ++index)
    {
        ASSERT_GT(written[index], std::size_t{0}) << errors[index];
        ASSERT_LE(written[index], signatures[index].size());
        const auto &reference = (0 == index) ? reference_a : reference_b;
        EXPECT_TRUE(mpss::verify(hash, reference.public_key, reference.algorithm,
                                 std::span<const std::byte>{signatures[index]}.first(written[index]), "yubikey"));
    }

    first_deleted = KeyPair::Delete(first);
    EXPECT_TRUE(first_deleted);
    EXPECT_EQ(nullptr, KeyPair::Open(first));
    EXPECT_NE(nullptr, KeyPair::Open(second));
}

TEST_F(MultiYubiKeyTest, KeysOnDifferentDevicesAreIndependent)
{
    const std::string key_name_a = test_key_name("test_multi_yk_a");
    const std::string key_name_b = test_key_name("test_multi_yk_b");

    // Clean up any leftovers, targeting each device in turn.
    for (const std::uint32_t serial : serials_)
    {
        TargetDevice(serial);
        auto leftover_a = mpss::KeyPair::Open(key_name_a, "yubikey");
        if (nullptr != leftover_a)
        {
            leftover_a->delete_key();
        }
        auto leftover_b = mpss::KeyPair::Open(key_name_b, "yubikey");
        if (nullptr != leftover_b)
        {
            leftover_b->delete_key();
        }
    }

    // Create key A on device 0.
    TargetDevice(serials_[0]);
    auto key_a = mpss::KeyPair::Create(key_name_a, ecdsa_secp256r1_sha256, "yubikey");
    ASSERT_NE(nullptr, key_a);

    // Create key B on device 1.
    TargetDevice(serials_[1]);
    auto key_b = mpss::KeyPair::Create(key_name_b, ecdsa_secp256r1_sha256, "yubikey");
    ASSERT_NE(nullptr, key_b);

    // Clear the env var - all operations should use the stored serial.
    ClearDeviceTarget();

    // Sign with both keys.
    const std::vector<std::byte> hash(32, static_cast<std::byte>('q'));

    const std::size_t sig_size_a = key_a->sign_hash(hash, {});
    std::vector<std::byte> sig_a(sig_size_a);
    const std::size_t written_a = key_a->sign_hash(hash, sig_a);
    ASSERT_GT(written_a, std::size_t{0});
    sig_a.resize(written_a);

    const std::size_t sig_size_b = key_b->sign_hash(hash, {});
    std::vector<std::byte> sig_b(sig_size_b);
    const std::size_t written_b = key_b->sign_hash(hash, sig_b);
    ASSERT_GT(written_b, std::size_t{0});
    sig_b.resize(written_b);

    // Each key verifies its own signature.
    EXPECT_TRUE(key_a->verify(hash, sig_a));
    EXPECT_TRUE(key_b->verify(hash, sig_b));

    // Cross-verification fails (different keys on different devices).
    EXPECT_FALSE(key_a->verify(hash, sig_b));
    EXPECT_FALSE(key_b->verify(hash, sig_a));

    // Clean up.
    key_a->delete_key();
    key_b->delete_key();
}

// The suite pins a serial, so automatic selection is exercised by clearing it here.
TEST_F(MultiYubiKeyTest, AnAmbiguousDeviceIsRefusedRatherThanGuessed)
{
    const auto refused_as_ambiguous = [] {
        const std::string error = mpss::get_error();
        return std::string::npos != error.find("Multiple YubiKeys detected");
    };

    const std::string key_name = test_key_name("ambiguous_device");
    const std::string absent_name = test_key_name("ambiguous_absent");

    // Put a key on a chosen device, so the open and delete refusals below are refusing to act on
    // something that really is there rather than merely failing to find it.
    TargetDevice(serials_[0]);
    std::unique_ptr<mpss::KeyPair> leftover = mpss::KeyPair::Open(key_name, "yubikey");
    if (nullptr != leftover)
    {
        leftover->delete_key();
        leftover.reset();
    }

    std::unique_ptr<mpss::KeyPair> created = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey");
    ASSERT_NE(nullptr, created);
    created.reset();

    ClearDeviceTarget();

    EXPECT_EQ(nullptr, mpss::KeyPair::Create(absent_name, ecdsa_secp256r1_sha256, "yubikey"));
    EXPECT_TRUE(refused_as_ambiguous()) << mpss::get_error();

    EXPECT_EQ(nullptr, mpss::KeyPair::Open(key_name, "yubikey"));
    EXPECT_TRUE(refused_as_ambiguous()) << mpss::get_error();

    EXPECT_FALSE(mpss::KeyPair::Delete(key_name, "yubikey"));
    EXPECT_TRUE(refused_as_ambiguous()) << mpss::get_error();

    // Refusing left everything as it was: the key is still on the device that holds it, and the
    // name the create was refused for was not taken on some other device.
    TargetDevice(serials_[0]);
    std::unique_ptr<mpss::KeyPair> reopened = mpss::KeyPair::Open(key_name, "yubikey");
    ASSERT_NE(nullptr, reopened);
    EXPECT_TRUE(reopened->delete_key());

    for (const std::uint32_t serial : serials_)
    {
        TargetDevice(serial);
        EXPECT_EQ(nullptr, mpss::KeyPair::Open(absent_name, "yubikey"));
    }
}

#ifndef MPSS_CORE_IS_SHARED
// A device allows only a few wrong PINs before it locks, and every operation asks for a PIN afresh, so a
// value a device has already refused must not be presented to it again. Device-independent -- these
// exercise the record directly, so they never spend a PIN attempt on hardware.
namespace
{
// The record is process-wide and cannot be reset, so each test needs serials no other test uses. These
// are outside the range real YubiKeys report.
[[nodiscard]]
std::uint32_t unique_test_serial()
{
    static std::uint32_t next = 0xF0000000;
    ++next;
    return next;
}
} // namespace

TEST(YubiKeyRejectedPins, ARejectedPinIsNotPresentedToTheSameDeviceAgain)
{
    using namespace mpss::impl::yubikey;

    const std::uint32_t serial = unique_test_serial();
    EXPECT_FALSE(pin_already_rejected(serial, "not-a-real-pin-a"));

    remember_rejected_pin(serial, "not-a-real-pin-a");
    EXPECT_TRUE(pin_already_rejected(serial, "not-a-real-pin-a"));

    // Only that value is refused; a different PIN is still worth presenting.
    EXPECT_FALSE(pin_already_rejected(serial, "not-a-real-pin-b"));

    // An empty PIN is not a value the device ever judged.
    remember_rejected_pin(serial, "");
    EXPECT_FALSE(pin_already_rejected(serial, ""));
    EXPECT_TRUE(pin_already_rejected(serial, "not-a-real-pin-a"));
}

TEST(YubiKeyRejectedPins, EveryRejectedPinStaysRejected)
{
    using namespace mpss::impl::yubikey;

    const std::uint32_t serial = unique_test_serial();
    remember_rejected_pin(serial, "not-a-real-pin-a");
    remember_rejected_pin(serial, "not-a-real-pin-b");

    // Recording the second must not forget the first, or cycling between two wrong values would spend a
    // retry on each pass.
    EXPECT_TRUE(pin_already_rejected(serial, "not-a-real-pin-a"));
    EXPECT_TRUE(pin_already_rejected(serial, "not-a-real-pin-b"));
    EXPECT_FALSE(pin_already_rejected(serial, "not-a-real-pin-c"));

    // Recording a value twice is harmless.
    remember_rejected_pin(serial, "not-a-real-pin-a");
    EXPECT_TRUE(pin_already_rejected(serial, "not-a-real-pin-a"));
}

TEST(YubiKeyRejectedPins, ValuesTheDeviceIsNotGivenAsWrittenAreIgnored)
{
    using namespace mpss::impl::yubikey;

    const std::uint32_t serial = unique_test_serial();

    // The device is handed a null-terminated string, so a value with an embedded null is not comparable
    // with what it actually saw.
    const std::string_view embedded_null{"not-a\0-real-pin", 15};
    remember_rejected_pin(serial, embedded_null);
    EXPECT_FALSE(pin_already_rejected(serial, embedded_null));

    remember_rejected_pin(serial, "");
    EXPECT_FALSE(pin_already_rejected(serial, ""));
}

TEST(YubiKeyRejectedPins, ARejectionOnOneDeviceDoesNotBlockAnother)
{
    using namespace mpss::impl::yubikey;

    const std::uint32_t rejecting_serial = unique_test_serial();
    const std::uint32_t other_serial = unique_test_serial();

    remember_rejected_pin(rejecting_serial, "not-a-real-pin-a");

    EXPECT_TRUE(pin_already_rejected(rejecting_serial, "not-a-real-pin-a"));
    // The same value may well be the correct PIN of a different device, so it must still be offered there.
    EXPECT_FALSE(pin_already_rejected(other_serial, "not-a-real-pin-a"));
}

TEST(YubiKeyDeviceIdentifier, AcceptsOnlyNonzeroDecimalSerials)
{
    using mpss::impl::yubikey::utils::parse_serial;

    EXPECT_EQ(std::uint32_t{1}, parse_serial("1"));
    EXPECT_EQ(std::uint32_t{123}, parse_serial("000123"));
    EXPECT_EQ(std::uint32_t{0xFFFFFFFF}, parse_serial("4294967295"));
    for (const auto *invalid : {"", "0", "0000", "-1", "+1", " 1", "1 ", "1x", "4294967296", "99999999999999999999999"})
    {
        EXPECT_FALSE(parse_serial(invalid).has_value()) << invalid;
    }
    EXPECT_FALSE(parse_serial(std::string_view{"12\0003", 4}).has_value());
    using mpss::impl::yubikey::utils::max_serial_length;
    EXPECT_EQ(std::uint32_t{1}, parse_serial(std::string(max_serial_length - 1, '0') + "1"));
    EXPECT_FALSE(parse_serial(std::string(max_serial_length, '0') + "1"));
}

TEST(YubiKeyDeviceIdentifier, EnvironmentUsesTheSameDecimalRules)
{
    using mpss::impl::yubikey::utils::get_serial_from_env;
    const char *value = std::getenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
    const std::optional<std::string> saved = value ? std::make_optional(std::string{value}) : std::nullopt;
    SCOPE_GUARD({
        if (saved)
        {
            setenv("MPSS_YUBIKEY_SERIAL", saved->c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        }
    });
    for (const char *invalid : {"4294967296", "-1", "+1", " 1", "1 ", "1x", "0", ""})
    {
        ASSERT_EQ(0, setenv("MPSS_YUBIKEY_SERIAL", invalid, 1)); // NOLINT(concurrency-mt-unsafe)
        EXPECT_FALSE(get_serial_from_env()) << invalid;
    }
    ASSERT_EQ(0, setenv("MPSS_YUBIKEY_SERIAL", "000123", 1)); // NOLINT(concurrency-mt-unsafe)
    EXPECT_EQ(std::uint32_t{123}, get_serial_from_env());
    ASSERT_EQ(0, setenv("MPSS_YUBIKEY_SERIAL", "4294967295", 1)); // NOLINT(concurrency-mt-unsafe)
    EXPECT_EQ(std::uint32_t{0xFFFFFFFF}, get_serial_from_env());
}

// The record only protects a device if the authentication path consults it, which the tests above cannot
// show. This drives a real operation instead. A passing run presents nothing to the device: the value is
// fabricated and already recorded as refused, so the operation must fail without reaching the card. Only a
// run that has already lost the guard spends a retry.
class YubiKeyPinGuard : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        serials_ = mpss::impl::yubikey::YubiKeyPIV::available_serials().value_or(std::vector<std::uint32_t>{});
        if (serials_.empty())
        {
            GTEST_SKIP() << "Requires a connected YubiKey.";
        }

        const char *value = std::getenv("MPSS_YUBIKEY_PIN"); // NOLINT(concurrency-mt-unsafe)
        saved_pin_ = (nullptr == value) ? std::nullopt : std::optional<std::string>{value};
    }

    void TearDown() override
    {
        restore_pin();
    }

    void restore_pin()
    {
        if (saved_pin_.has_value())
        {
            setenv("MPSS_YUBIKEY_PIN", saved_pin_->c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
        else
        {
            unsetenv("MPSS_YUBIKEY_PIN"); // NOLINT(concurrency-mt-unsafe)
        }
    }

    std::vector<std::uint32_t> serials_; // NOLINT(misc-non-private-member-variables-in-classes)

  private:
    std::optional<std::string> saved_pin_;
};

TEST_F(YubiKeyPinGuard, AnAlreadyRejectedPinIsNotPresentedToTheDevice)
{
    const std::string key_name = test_key_name("mpss_yk_pin_guard");
    MPSS::DeleteKey(key_name);

    std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey");
    if (nullptr == handle)
    {
        GTEST_SKIP() << "Connected YubiKey cannot create keys in its current state.";
    }

    // A value the device has never been given, recorded as though it had refused it.
    const std::string fabricated = "not-a-real-pin-d";
    mpss::impl::yubikey::remember_rejected_pin(serials_[0], fabricated);
    setenv("MPSS_YUBIKEY_PIN", fabricated.c_str(), 1); // NOLINT(concurrency-mt-unsafe)

    const std::vector<std::byte> hash(32, static_cast<std::byte>('h'));
    std::vector<std::byte> signature(handle->sign_hash_size());
    EXPECT_EQ(0, handle->sign_hash(hash, signature));

    // The refusal must come from the record, not from the device rejecting the value.
    EXPECT_NE(std::string::npos, mpss::get_error().find("already rejected"));

    restore_pin();
    MPSS::DeleteKey(key_name);
}

// Every PIN request must be answered by exactly one result, including when the PIN never reaches the
// device: a handler that opened UI while answering the request has nothing else to tell it to close.
namespace
{
class CountingHandler : public mpss::InteractionHandler
{
  public:
    explicit CountingHandler(std::optional<mpss::SecureString> pin) : pin_{std::move(pin)}
    {
    }

    std::optional<mpss::SecureString> request_pin(const mpss::PinRequestContext &context) override
    {
        ++requests;
        backend = context.target.backend_name;
        device = context.target.device_id;
        key_name = context.target.key_name;
        reader = context.target.reader_name;
        if (throw_from_request)
        {
            throw std::runtime_error{"handler failure"};
        }
        return pin_;
    }

    void notify_pin_result(const mpss::InteractionContext &target, mpss::PinResult result,
                           int /*retries_remaining*/) override
    {
        EXPECT_EQ(backend, target.backend_name);
        EXPECT_EQ(device, target.device_id);
        EXPECT_EQ(key_name, target.key_name);
        EXPECT_EQ(reader, target.reader_name);
        ++results;
        last_result = result;
    }

    void notify_touch_needed(const mpss::InteractionContext & /*target*/) override
    {
    }

    void notify_touch_complete(const mpss::InteractionContext & /*target*/, bool /*success*/) override
    {
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes) - a test double.
    int requests{0};
    int results{0};
    bool throw_from_request{false};
    mpss::PinResult last_result{mpss::PinResult::ok};
    std::string backend;
    std::string device;
    std::string key_name;
    std::string reader;
    // NOLINTEND(misc-non-private-member-variables-in-classes)

  private:
    std::optional<mpss::SecureString> pin_;
};

class RestoreHandler
{
  public:
    RestoreHandler() = default;
    RestoreHandler(const RestoreHandler &) = delete;
    RestoreHandler(RestoreHandler &&) = delete;
    RestoreHandler &operator=(const RestoreHandler &) = delete;
    RestoreHandler &operator=(RestoreHandler &&) = delete;
    ~RestoreHandler()
    {
        mpss::ResetDefaultInteractionHandler();
    }
};
} // namespace

TEST_F(YubiKeyPinGuard, EveryPinRequestIsAnsweredByExactlyOneResult)
{
    const RestoreHandler restore;

    // A value recorded as refused, so MPSS withholds it and never reaches the device.
    const std::string withheld = "not-a-real-pin-e";
    mpss::impl::yubikey::remember_rejected_pin(serials_[0], withheld);

    const std::string key_name = test_key_name("mpss_yk_one_result");
    MPSS::DeleteKey(key_name);
    std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256, "yubikey");
    if (nullptr == handle)
    {
        GTEST_SKIP() << "Connected YubiKey cannot create keys in its current state.";
    }

    const std::vector<std::byte> hash(32, static_cast<std::byte>('h'));
    std::vector<std::byte> signature(handle->sign_hash_size());

    auto withholding = std::make_shared<CountingHandler>(mpss::SecureString{withheld.c_str()});
    mpss::GetOrSetInteractionHandler(withholding);
    EXPECT_EQ(0, handle->sign_hash(hash, signature));
    EXPECT_EQ(withholding->requests, withholding->results);
    EXPECT_EQ(mpss::PinResult::not_attempted, withholding->last_result);
    EXPECT_EQ("yubikey", withholding->backend);
    EXPECT_EQ(std::to_string(serials_[0]), withholding->device);
    EXPECT_EQ(key_name, withholding->key_name);
    EXPECT_FALSE(withholding->reader.empty());

    // Cancelling is answered too, so a handler that cancels still hears back.
    auto cancelling = std::make_shared<CountingHandler>(std::nullopt);
    mpss::GetOrSetInteractionHandler(cancelling);
    EXPECT_EQ(0, handle->sign_hash(hash, signature));
    EXPECT_EQ(cancelling->requests, cancelling->results);
    EXPECT_EQ(mpss::PinResult::not_attempted, cancelling->last_result);

    // A handler that throws is answered as well, and its exception does not escape the operation.
    auto throwing = std::make_shared<CountingHandler>(std::nullopt);
    throwing->throw_from_request = true;
    mpss::GetOrSetInteractionHandler(throwing);
    EXPECT_EQ(0, handle->sign_hash(hash, signature));
    EXPECT_EQ(throwing->requests, throwing->results);
    EXPECT_EQ(mpss::PinResult::not_attempted, throwing->last_result);

    mpss::ResetDefaultInteractionHandler();
    MPSS::DeleteKey(key_name);
}
#endif // MPSS_CORE_IS_SHARED

#endif // MPSS_BACKEND_YUBIKEY

} // namespace mpss::tests
