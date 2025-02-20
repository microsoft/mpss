// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include <gtest/gtest.h>
#include <utility>

namespace mpss {
    namespace tests {
        using std::operator""s;
        using std::operator""sv;

        class MPSS : public ::testing::Test {
        public:
            static void DeleteKey(std::string name) {
                // Check if key exists, delete if it does
                std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::open(name);
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

            static std::unique_ptr<mpss::KeyPair> CreateKey(std::string name, SignatureAlgorithm algorithm) {
                // Create a key pair
                std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::create(std::move(name), algorithm);
                if (handle == nullptr) {
                    std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
                }
                return handle;
            }
        };

        void SignAndVerify(SignatureAlgorithm algorithm, std::string_view suffix, int hash_size)
        {
            std::string key_name = "test_key_"s + suffix.data();

            // Delete key if it exists
            MPSS::DeleteKey(key_name);

            // Create a key pair for testing
            std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
            ASSERT_TRUE(handle != nullptr);

            // Sign the data
            std::vector<std::byte> hash(hash_size, static_cast<std::byte>('a'));
            std::optional<std::vector<std::byte>> signature = handle->sign(hash);
            if (!signature.has_value()) {
                std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(signature.has_value());

            // Verify the data
            ASSERT_TRUE(handle->verify(hash, signature.value()));

            // Release the key pair handle
            handle->release_key();

            // Delete the key pair
            MPSS::DeleteKey(key_name);
        }

        TEST_F(MPSS, SignAndVerify256) {
            SignAndVerify(SignatureAlgorithm::ECDSA_P256_SHA256, "256", 32);
        }

        TEST_F(MPSS, SignAndVerify384) {
            SignAndVerify(SignatureAlgorithm::ECDSA_P384_SHA384, "384", 48);
        }

        TEST_F(MPSS, SignAndVerify521) {
            SignAndVerify(SignatureAlgorithm::ECDSA_P521_SHA512, "521", 64);
        }

        void GetKey(SignatureAlgorithm algorithm, std::string_view suffix)
        {
            std::string key_name = "test_key_2_"s + suffix.data();

            // Delete key if it exists
            MPSS::DeleteKey(key_name);

            // Create a key pair for testing
            std::unique_ptr<mpss::KeyPair> handle = MPSS::CreateKey(key_name, algorithm);
            ASSERT_TRUE(handle != nullptr);

            // Get the key pair
            std::vector<std::byte> vk;
            bool got_key = handle->get_verification_key(vk);
            if (!got_key) {
                std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(got_key);
            std::cout << "VK size: " << vk.size() << std::endl;
            ASSERT_TRUE(vk.size() > 0);

            // Release the key pair handle
            handle->release_key();

            // Delete the key pair
            MPSS::DeleteKey(key_name);
        }

        TEST_F(MPSS, GetKey256) {
            GetKey(SignatureAlgorithm::ECDSA_P256_SHA256, "256");
        }

        TEST_F(MPSS, GetKey384) {
            GetKey(SignatureAlgorithm::ECDSA_P384_SHA384, "384");
        }

        TEST_F(MPSS, GetKey521) {
            GetKey(SignatureAlgorithm::ECDSA_P521_SHA512, "521");
        }
    }
}
