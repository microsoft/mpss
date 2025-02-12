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
                std::unique_ptr<mpss::KeyPairHandle> handle = mpss::open_key(name);
                if (handle != nullptr) {
                    bool deleted = mpss::delete_key(*handle);
                    if (!deleted) {
                        std::cout << "Key could not be deleted: " << mpss::get_error() << std::endl;
                    }
                    ASSERT_TRUE(deleted);
                }
                else {
                    std::cout << "Key does not exist: " << mpss::get_error() << std::endl;
                }
            }

            static std::unique_ptr<mpss::KeyPairHandle> CreateKey(std::string name, SignatureAlgorithm algorithm) {
                // Create a key pair
                std::unique_ptr<mpss::KeyPairHandle> handle = mpss::create_key(std::move(name), algorithm);
                if (handle == nullptr) {
                    std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
                }
                return handle;
            }
        };

        void SignAndVerify(SignatureAlgorithm algorithm, std::string_view suffix)
        {
			std::string key_name = "test_key_"s + suffix.data();

            // Delete key if it exists
            MPSS::DeleteKey(key_name);

            // Create a key pair for testing
            std::unique_ptr<mpss::KeyPairHandle> handle = MPSS::CreateKey(key_name, algorithm);
            ASSERT_TRUE(handle != nullptr);

            // Sign the data
            std::string hash(handle->hash_size(), 'a');
            std::optional<std::string> signature = mpss::sign(*handle, hash);
            if (!signature.has_value()) {
                std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(signature.has_value());

            // Verify the data
            ASSERT_TRUE(mpss::verify(*handle, hash, signature.value()));

            // Release the key pair handle
            mpss::release_key(*handle);

            // Delete the key pair
            MPSS::DeleteKey(key_name);
        }

        TEST_F(MPSS, SignAndVerify256) {
			SignAndVerify(SignatureAlgorithm::ECDSA_P256_SHA256, "256");
        }

        TEST_F(MPSS, SignAndVerify384) {
            SignAndVerify(SignatureAlgorithm::ECDSA_P384_SHA384, "384");
        }

		TEST_F(MPSS, SignAndVerify521) {
			SignAndVerify(SignatureAlgorithm::ECDSA_P521_SHA512, "521");
		}

        void GetKey(SignatureAlgorithm algorithm, std::string_view suffix)
        {
            std::string key_name = "test_key_2_"s + suffix.data();

            // Delete key if it exists
            MPSS::DeleteKey(key_name);

            // Create a key pair for testing
            std::unique_ptr<mpss::KeyPairHandle> handle = MPSS::CreateKey(key_name, algorithm);
            ASSERT_TRUE(handle != nullptr);

            // Get the key pair
            std::string vk;
            bool got_key = mpss::get_key(*handle, vk);
            if (!got_key) {
                std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(got_key);
            std::cout << "VK size: " << vk.size() << std::endl;
            ASSERT_TRUE(vk.size() > 0);

            // Release the key pair handle
            mpss::release_key(*handle);

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
