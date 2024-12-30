// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Google Test
#include <gtest/gtest.h>

// MPSS
#include "mpss/mpss.h"

namespace mpss {
    namespace tests {
        class MPSS : public ::testing::Test {
        protected:
            void SetUp() override {
                // Check if key exists, delete if it does
                bool deleted = mpss::delete_key("test_key");
                if (!deleted) {
                    std::cout << "Key does not exist or could not be deleted: " << mpss::get_error() << std::endl;
                }
                else {
                    std::cout << "Key deleted" << std::endl;
                }

                // Create a key pair
                bool created = mpss::create_key("test_key");
                if (!created) {
                    std::cout << "Key could not be created: " << mpss::get_error() << std::endl;
                }
                ASSERT_TRUE(created);
            }
            void TearDown() override {
                // Delete the key pair
                ASSERT_TRUE(mpss::delete_key("test_key"));
            }
        };

        TEST_F(MPSS, SignAndVerify) {
            // Sign the data
            auto signature = mpss::sign("test_key", "test_data");
            ASSERT_TRUE(signature.has_value());
            // Verify the data
            ASSERT_TRUE(mpss::verify("test_key", "test_data", signature.value()));
        }

        TEST_F(MPSS, SetAndGetKey) {
            // Set the key pair
            ASSERT_TRUE(mpss::set_key("test_key", "test_vk", "test_sk"));
            // Get the key pair
            std::string vk, sk;
            ASSERT_TRUE(mpss::get_key("test_key", vk, sk));
            ASSERT_EQ(vk, "test_vk");
            ASSERT_EQ(sk, "test_sk");
        }
    }
}