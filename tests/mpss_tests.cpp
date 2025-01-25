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

        TEST_F(MPSS, SignAndVerify) {
            // Delete key if it exists
            MPSS::DeleteKey("test_key"s);

            // Create a key pair for testing
            MPSS::CreateKey("test_key"s, SignatureAlgorithm::ECDSA_P256_SHA256);

            // Sign the data
            std::optional<std::string> signature = mpss::sign("test_key"sv, "test_data"s, SignatureAlgorithm::ECDSA_P256_SHA256);
            if (!signature.has_value()) {
                std::cout << "Data could not be signed: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(signature.has_value());

            // Verify the data
            ASSERT_TRUE(mpss::verify("test_key"sv, "test_data"s, signature.value(), SignatureAlgorithm::ECDSA_P256_SHA256));

            // Delete the key pair
            MPSS::DeleteKey("test_key"s);
        }

        TEST_F(MPSS, GetKey) {
            // Delete key if it exists
            DeleteKey("test_key_2");

            // Create a key pair for testing
            CreateKey("test_key_2", SignatureAlgorithm::ECDSA_P384_SHA384);

            // Get the key pair
            std::string vk;
            bool got_key = mpss::get_key("test_key_2", SignatureAlgorithm::ECDSA_P384_SHA384, vk);
            if (!got_key) {
                std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(got_key);
            std::cout << "VK size: " << vk.size() << std::endl;
            ASSERT_TRUE(vk.size() > 0);

            // Delete the key pair
            DeleteKey("test_key_2");
        }
    }
}