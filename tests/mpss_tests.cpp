// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include <gtest/gtest.h>
#include <utility>

namespace mpss::tests {
    using std::operator""s;
    using std::operator""sv;

    class MPSS : public ::testing::Test {
    public:
        static void DeleteKey(std::string name) {
            // Check if key exists, delete if it does
            std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Open(name);
            if (handle != nullptr) {
                bool deleted = handle->delete_key();
                if (!deleted) {
                    std::cout << "Key could not be deleted: " << mpss::get_error() << std::endl;
                }
                ASSERT_TRUE(deleted);
            }
            else {
                std::cout << "Key does not exist: " << mpss::get_error() << std::endl;
            }
        }

        static std::unique_ptr<mpss::KeyPair> CreateKey(std::string name, Algorithm algorithm) {
            // Create a key pair
            std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(std::move(name), algorithm);
            if (handle == nullptr) {
                std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
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

        // Sign the data
        std::vector<std::byte> hash(hash_size, static_cast<std::byte>('a'));
        
        // First extract the size of the 
        std::size_t sig_size = handle->sign_hash(hash, {});
        std::vector<std::byte> signature(sig_size);
        std::size_t written = handle->sign_hash(hash, signature);
        if (0 == written) {
            std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
        }
        ASSERT_EQ(written, sig_size);

        // Verify the data
        ASSERT_TRUE(handle->verify(hash, signature));

        // Release the key pair handle
        handle->release_key();

        // Delete the key pair
        MPSS::DeleteKey(key_name);
    }

    TEST_F(MPSS, SignAndVerify256) {
        SignAndVerify(Algorithm::ECDSA_P256_SHA256, "256", 32);
    }

    TEST_F(MPSS, SignAndVerify384) {
        SignAndVerify(Algorithm::ECDSA_P384_SHA384, "384", 48);
    }

    TEST_F(MPSS, SignAndVerify521) {
        SignAndVerify(Algorithm::ECDSA_P521_SHA512, "521", 64);
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
        ASSERT_TRUE(vk_size == read);
        std::cout << "VK size: " << vk_size << std::endl;

        // Release the key pair handle
        handle->release_key();

        // Delete the key pair
        MPSS::DeleteKey(key_name);
    }

    TEST_F(MPSS, GetKey256) {
        GetKey(Algorithm::ECDSA_P256_SHA256, "256");
    }

    TEST_F(MPSS, GetKey384) {
        GetKey(Algorithm::ECDSA_P384_SHA384, "384");
    }

    TEST_F(MPSS, GetKey521) {
        GetKey(Algorithm::ECDSA_P521_SHA512, "521");
    }
}
