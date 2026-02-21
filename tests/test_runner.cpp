// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <gtest/gtest.h>

#include "mpss/log.h"

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    mpss::GetLogger()->set_level(mpss::LogLevel::DEBUG);
    return RUN_ALL_TESTS();
}