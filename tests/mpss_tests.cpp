// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/key_policy.h"
#include "mpss/log.h"
#include "mpss/mpss.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

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
        while (true)
        {
            // Check if key exists, delete if it does.
            std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Open(name);
            if (nullptr == handle)
            {
                break;
            }
            const bool deleted = handle->delete_key();
            if (!deleted)
            {
                mpss::GetLogger()->error("Key could not be deleted: {}", mpss::get_error());
            }
            ASSERT_TRUE(deleted);
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

    const std::string key_name = "test_key_"s + suffix.data();

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

    const std::string key_name = "creation_test_"s + suffix.data();

    // Delete key if it exists
    MPSS::DeleteKey(key_name);

    // Create the key pair
    std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(key_name, algorithm);
    ASSERT_NE(nullptr, handle);

    // Try to create the key pair again
    std::unique_ptr<mpss::KeyPair> handle2 = mpss::KeyPair::Create(key_name, algorithm);
    // It should fail
    ASSERT_EQ(nullptr, handle2);

    // Delete the key pair
    bool deleted = false;
    if (nullptr != handle)
    {
        deleted = handle->delete_key();
    }
    ASSERT_TRUE(deleted);
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

void GetKey(Algorithm algorithm, std::string_view suffix)
{
    if (!mpss::is_algorithm_available(algorithm))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = "test_key_2_"s + suffix.data();

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

    const std::string key_name = "test_key_3_"s + suffix.data();

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

    const std::string key_name = "test_key_4_"s + suffix.data();
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

TEST(BackendTest, CreateKeyWithExplicitBackend)
{
    const char *const default_backend = mpss::get_default_backend_name();
    ASSERT_NE(nullptr, default_backend);
    ASSERT_GT(std::strlen(default_backend), std::size_t{0});

    const std::string key_name = "test_explicit_key";
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

    const std::string key_name = "test_explicit_open_key";
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

    const std::string key_name = "test_backend_name_create";
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

    const std::string key_name = "test_backend_name_create_explicit";
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

    const std::string key_name = "test_backend_name_open";
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

    const std::string key_name = "test_backend_name_open_explicit";
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
    auto key = mpss::KeyPair::Create("test_bad_backend", ecdsa_secp256r1_sha256, "nonexistent");
    EXPECT_EQ(nullptr, key);
}

TEST(BackendTest, OpenKeyWithInvalidBackend)
{
    auto key = mpss::KeyPair::Open("test_bad_backend", "nonexistent");
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

    const std::string key_name = "test_verify_explicit";
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

#ifdef MPSS_BACKEND_YUBIKEY

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

#endif // MPSS_BACKEND_YUBIKEY

TEST(KeyPolicyTest, CreateKeyWithPolicyNone)
{
    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = "test_key_policy_none";
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

    const std::string key_name(64, 'k');
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
    std::string name_a(64, 'k');
    std::string name_b(64, 'k');
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
    const std::string key_name = "test_cross_backend_sign";
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
    const std::string os_key_name = "test_cross_os_key";
    const std::string yk_key_name = "test_cross_yk_key";

    MPSS::DeleteKey(os_key_name);

    // Create a key on the OS backend.
    auto os_key = mpss::KeyPair::Create(os_key_name, ecdsa_secp256r1_sha256, "os");
    ASSERT_NE(nullptr, os_key);

    // Create a key on the YubiKey backend.
    auto yk_key = mpss::KeyPair::Create(yk_key_name, ecdsa_secp256r1_sha256, "yubikey");
    ASSERT_NE(nullptr, yk_key);

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

} // namespace mpss::tests
