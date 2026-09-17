// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#import <XCTest/XCTest.h>

#include "tests/test_entry.h"

#include <format>
#include <string>

#include <gtest/gtest.h>

@interface MPSSNativeTests : XCTestCase
@end

@implementation MPSSNativeTests

- (void)testNativeSuite {
  char executable_name[] = "mpss_ios_xctest";
  char *argv[] = {executable_name, nullptr};
  const int result = mpss::tests::run_all_tests(1, argv);

  const auto *unit_test = ::testing::UnitTest::GetInstance();
  const int total = unit_test->test_to_run_count();
  const int passed = unit_test->successful_test_count();
  const int skipped = unit_test->skipped_test_count();
  const int failed = unit_test->failed_test_count();

  if (0 != result || 0 != failed) {
    const std::string message =
        std::format("Native GoogleTest suite failed: exit={}, total={}, passed={}, skipped={}, failed={}", result,
                    total, passed, skipped, failed);
    NSString *description = [NSString stringWithUTF8String:message.c_str()];
    XCTIssue *issue = [[XCTIssue alloc] initWithType:XCTIssueTypeAssertionFailure
                                  compactDescription:description
                                 detailedDescription:nil
                                   sourceCodeContext:[[XCTSourceCodeContext alloc] init]
                                     associatedError:nil
                                         attachments:@[]];
    [self recordIssue:issue];
  }
}

@end
