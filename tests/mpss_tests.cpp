// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <gtest/gtest.h>
#include "mpss/mpss.h"
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace mpss::tests {
    using namespace mpss;
    using std::operator""s;
    using std::operator""sv;

    class MPSS : public ::testing::Test {
    public:
        static void DeleteKey(std::string name)
        {
            for (int i = 0; i < 3; i++) {
                // Check if key exists, delete if it does
                std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Open(name);
                if (handle != nullptr) {
                    bool deleted = handle->delete_key();
                    if (!deleted) {
                        std::cout << "Key could not be deleted: " << mpss::get_error() << std::endl;
                    }
                    ASSERT_TRUE(deleted);
                } else {
                    std::cout << "Key does not exist: " << mpss::get_error() << std::endl;
                }
            }
        }

        static std::unique_ptr<mpss::KeyPair> CreateKey(std::string name, Algorithm algorithm)
        {
            // Create a key pair
            std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(std::move(name), algorithm);
            if (handle == nullptr) {
                std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
            } else {
                std::cout << "Key " << name << " created in " << handle->key_info().storage_description
                          << ". Hardware backed: " << handle->key_info().is_hardware_backed << std::endl;
            }
            return handle;
        }
    };

    void SignAndVerify(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
    {
        std::string key_name = "test_key_"s + suffix.data();

        // Delete key if it exists
        MPSS::DeleteKey(key_name);

        // Create a key pair for testing
        std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
        ASSERT_TRUE(handle != nullptr);

        // Test invalid hash size
        std::vector<std::byte> invalid_hash(hash_size - 1, static_cast<std::byte>('b'));
        std::size_t sig_size = handle->sign_hash(invalid_hash, {});
        ASSERT_EQ(0, sig_size);
        std::cout << "Expected error: " << mpss::get_error() << std::endl;

        // Sign the data
        std::vector<std::byte> hash(hash_size, static_cast<std::byte>('a'));

        // First extract the size of the signature
        sig_size = handle->sign_hash(hash, {});
        std::vector<std::byte> signature(sig_size);
        std::size_t written = handle->sign_hash(hash, signature);
        if (0 == written) {
            std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
        }
        ASSERT_GE(sig_size, written);

        // Verify the data. Signature needs to be resized to the actual size written.
        signature.resize(written);

        // Sign a second time to verify we get different signatures when signing the same data
        std::vector<std::byte> signature2(sig_size);
        written = handle->sign_hash(hash, signature2);
        if (0 == written) {
            std::cout << "Data could not be signed second time: " << mpss::get_error() << std::endl;
        }
        ASSERT_GE(sig_size, written);

        signature2.resize(written);
        ASSERT_NE(signature, signature2);

        // Verify first signature
        bool verified = handle->verify(hash, signature);
        if (!verified) {
            std::cout << "Signature 1 could not be verified: " << mpss::get_error() << std::endl;
        }
        ASSERT_TRUE(verified);

        // Verify second signature
        verified = handle->verify(hash, signature2);
        if (!verified) {
            std::cout << "Signature 2 could not be verified: " << mpss::get_error() << std::endl;
        }
        ASSERT_TRUE(verified);

        // Release the key pair
        handle->release_key();

        // Delete the key pair
        MPSS::DeleteKey(key_name);
    }

    void DoubleCreation(Algorithm algorithm, std::string_view suffix)
    {
        std::string key_name = "creation_test_"s + suffix.data();

        // Delete key if it exists
        MPSS::DeleteKey(key_name);

        // Create the key pair
        std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(key_name, algorithm);
        ASSERT_TRUE(handle != nullptr);

        // Try to create the key pair again
        std::unique_ptr<mpss::KeyPair> handle2 = mpss::KeyPair::Create(key_name, algorithm);
        // It should fail
        ASSERT_TRUE(handle2 == nullptr);

        // Delete the key pair
        bool deleted = false;
        if (nullptr != handle) {
            deleted = handle->delete_key();
        }
        ASSERT_TRUE(deleted);
    }

    TEST_F(MPSS, SignAndVerify256)
    {
        SignAndVerify(Algorithm::ecdsa_secp256r1_sha256, "256", 32);
    }

    TEST_F(MPSS, SignAndVerify384)
    {
        SignAndVerify(Algorithm::ecdsa_secp384r1_sha384, "384", 48);
    }

    TEST_F(MPSS, SignAndVerify521)
    {
        SignAndVerify(Algorithm::ecdsa_secp521r1_sha512, "521", 64);
    }

    TEST_F(MPSS, DoubleCreation256)
    {
        DoubleCreation(Algorithm::ecdsa_secp256r1_sha256, "256");
    }

    TEST_F(MPSS, DoubleCreation384)
    {
        DoubleCreation(Algorithm::ecdsa_secp384r1_sha384, "384");
    }

    TEST_F(MPSS, DoubleCreation521)
    {
        DoubleCreation(Algorithm::ecdsa_secp521r1_sha512, "521");
    }

    void GetKey(Algorithm algorithm, std::string_view suffix)
    {
        std::string key_name = "test_key_2_"s + suffix.data();

        // Delete key if it exists
        MPSS::DeleteKey(key_name);

        // Create a key pair for testing
        std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
        ASSERT_TRUE(handle != nullptr);

        // Get the key pair
        std::size_t vk_size = handle->extract_key({});
        std::vector<std::byte> vk(vk_size);
        std::size_t read = handle->extract_key(vk);
        if (0 == read) {
            std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
        }
        std::cout << "VK size: " << vk_size << " read: " << read << std::endl;
        ASSERT_EQ(vk_size, read);

        // Release the key pair handle
        handle->release_key();

        // Delete the key pair
        MPSS::DeleteKey(key_name);
    }

    void GetKeySmallBuffer(Algorithm algorithm, std::string_view suffix)
    {
        std::string key_name = "test_key_3_"s + suffix.data();

        // Delete key if it exists
        MPSS::DeleteKey(key_name);

        // Create a key pair for testing
        std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
        ASSERT_TRUE(handle != nullptr);

        // Get the key pair
        std::size_t vk_size = handle->extract_key({});
        std::vector<std::byte> vk(vk_size - 1);
        std::size_t read = handle->extract_key(vk);
        if (0 == read) {
            std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
        }
        ASSERT_EQ(0, read);

        // Release the key pair handle
        handle->release_key();

        // Delete the key pair
        MPSS::DeleteKey(key_name);
    }

    TEST_F(MPSS, GetKey256)
    {
        GetKey(Algorithm::ecdsa_secp256r1_sha256, "256");
    }

    TEST_F(MPSS, GetKey384)
    {
        GetKey(Algorithm::ecdsa_secp384r1_sha384, "384");
    }

    TEST_F(MPSS, GetKey521)
    {
        GetKey(Algorithm::ecdsa_secp521r1_sha512, "521");
    }

    TEST_F(MPSS, GetKeySmallBuffer256)
    {
        GetKeySmallBuffer(Algorithm::ecdsa_secp256r1_sha256, "256");
    }

    TEST_F(MPSS, GetKeySmallBuffer384)
    {
        GetKeySmallBuffer(Algorithm::ecdsa_secp384r1_sha384, "384");
    }

    TEST_F(MPSS, GetKeySmallBuffer521)
    {
        GetKeySmallBuffer(Algorithm::ecdsa_secp521r1_sha512, "521");
    }

    void VerifyStandaloneSignature(Algorithm algorithm, std::string_view suffix, std::size_t hash_size)
    {
        std::string key_name = "test_key_4_"s + suffix.data();
        // Delete key if it exists
        MPSS::DeleteKey(key_name);

        // Create a key pair for testing
        std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
        ASSERT_TRUE(handle != nullptr);

        // Sign the data
        std::vector<std::byte> hash(hash_size, static_cast<std::byte>('a'));
        std::size_t sig_size = handle->sign_hash(hash, {});
        std::vector<std::byte> signature(sig_size);
        std::size_t written = handle->sign_hash(hash, signature);
        if (0 == written) {
            std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
        }
        ASSERT_GE(sig_size, written);
        signature.resize(written);

        // Get the public key
        std::size_t vk_size = handle->extract_key({});
        std::vector<std::byte> vk(vk_size);
        std::size_t read = handle->extract_key(vk);
        if (0 == read) {
            std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
        }
        std::cout << "VK size: " << vk_size << std::endl;
        ASSERT_EQ(vk_size, read);

        // Release the key pair handle
        handle->release_key();

        // Delete the key pair
        MPSS::DeleteKey(key_name);

        // The key should not exist anymore, so try to verify with the public key
        bool verified = mpss::verify(hash, vk, algorithm, signature);
        if (!verified) {
            std::cout << "Data could not be verified: " << mpss::get_error() << std::endl;
        }
        ASSERT_TRUE(verified);
    }

    TEST_F(MPSS, VerifyStandaloneSignature256)
    {
        VerifyStandaloneSignature(Algorithm::ecdsa_secp256r1_sha256, "256", 32);
    }

    TEST_F(MPSS, VerifyStandaloneSignature384)
    {
        VerifyStandaloneSignature(Algorithm::ecdsa_secp384r1_sha384, "384", 48);
    }

    TEST_F(MPSS, VerifyStandaloneSignature521)
    {
        VerifyStandaloneSignature(Algorithm::ecdsa_secp521r1_sha512, "521", 64);
    }

    TEST(MPSSTests, IsAlgorithmSupported)
    {
        ASSERT_NO_THROW({
            bool supported = mpss::is_algorithm_supported(Algorithm::ecdsa_secp256r1_sha256);
            std::cout << "Algorithm ecdsa_secp256r1_sha256 supported: " << supported << std::endl;
        });
        ASSERT_NO_THROW({
            bool supported = mpss::is_algorithm_supported(Algorithm::ecdsa_secp384r1_sha384);
            std::cout << "Algorithm ecdsa_secp384r1_sha384 supported: " << supported << std::endl;
        });
        ASSERT_NO_THROW({
            bool supported = mpss::is_algorithm_supported(Algorithm::ecdsa_secp521r1_sha512);
            std::cout << "Algorithm ecdsa_secp521r1_sha512 supported: " << supported << std::endl;
        });
    }

    TEST(MPSSTests, IsAlgorithmSupported256)
    {
        // All platforms should support P256 at least
        ASSERT_NO_THROW({
            bool supported = mpss::is_algorithm_supported(Algorithm::ecdsa_secp256r1_sha256);
            ASSERT_TRUE(supported);
        });
    }
} // namespace mpss::tests
