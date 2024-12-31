// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Google Test
#include <gtest/gtest.h>

// MPSS
#include "mpss/mpss.h"

namespace mpss {
    namespace tests {
        class MPSS : public ::testing::Test {
        public:
            static void DeleteKey(const std::string& name) {
                // Check if key exists, delete if it does
                bool deleted = mpss::delete_key(name);
                if (!deleted) {
                    std::cout << "Key does not exist or could not be deleted: " << mpss::get_error() << std::endl;
                }
                ASSERT_TRUE(deleted);
            }

            static void CreateKey(const std::string& name) {
                // Create a key pair
                bool created = mpss::create_key(name);
                if (!created) {
                    std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
                }
                ASSERT_TRUE(created);
            }
        };

        TEST_F(MPSS, SignAndVerify) {
            // Delete key if it exists
            MPSS::DeleteKey("test_key");

            // Create a key pair for testing
            MPSS::CreateKey("test_key");

            // Sign the data
            auto signature = mpss::sign("test_key", "test_data");
            ASSERT_TRUE(signature.has_value());

            // Verify the data
            ASSERT_TRUE(mpss::verify("test_key", "test_data", signature.value()));

            // Delete the key pair
            MPSS::DeleteKey("test_key");
        }

        TEST_F(MPSS, SetAndGetKey) {
            // Delete key if it exists
            DeleteKey("test_key_2");

            // Create a key pair for testing
            CreateKey("test_key_2");

            // Get the key pair
            std::string vk, sk;
            bool got_key = mpss::get_key("test_key_2", vk, sk);
            if (!got_key) {
                std::cout << "Key could not be retrieved: " << mpss::get_error() << std::endl;
            }
            ASSERT_TRUE(got_key);
            std::cout << "VK size: " << vk.size() << std::endl;
            std::cout << "SK size: " << sk.size() << std::endl;
            ASSERT_TRUE(vk.size() > 0);
            ASSERT_TRUE(sk.size() > 0);

            // Delete the key pair
            DeleteKey("test_key_2");
        }
    }
}