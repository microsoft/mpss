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
                bool deleted = mpss::delete_key(std::move(name));
                if (!deleted) {
                    std::cout << "Key does not exist or could not be deleted: " << mpss::get_error() << std::endl;
                }
                ASSERT_TRUE(deleted);
            }

            static void CreateKey(std::string name, SignatureAlgorithm algorithm) {
                // Create a key pair
                bool created = mpss::create_key(std::move(name), algorithm);
                if (!created) {
                    std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
                }
                ASSERT_TRUE(created);
            }
        };

        void SignAndVerify(SignatureAlgorithm algorithm, std::string_view suffix, int hash_size)
        {
			std::string key_name = "test_key_"s + suffix.data();

            // Delete key if it exists
            MPSS::DeleteKey(key_name);

            // Create a key pair for testing
            MPSS::CreateKey(key_name, algorithm);

            // Sign the data
            std::string hash(hash_size, 'a');
            std::optional<std::string> signature = mpss::sign(key_name, hash, algorithm);
            if (!signature.has_value()) {
                std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(signature.has_value());

            // Verify the data
            ASSERT_TRUE(mpss::verify(key_name, hash, signature.value(), algorithm));

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
            MPSS::CreateKey(key_name, algorithm);

            // Get the key pair
            std::string vk;
            bool got_key = mpss::get_key(key_name, algorithm, vk);
            if (!got_key) {
                std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(got_key);
            std::cout << "VK size: " << vk.size() << std::endl;
            ASSERT_TRUE(vk.size() > 0);

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
