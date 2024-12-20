// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// Google Test
#include <gtest/gtest.h>

// MPSS
#include "mpss/mpss.h"

namespace mpss {
    namespace tests {
        TEST(MpssTests, MyFunTest) {
            myfun();
            EXPECT_EQ(1, 1);
        }
    }
}