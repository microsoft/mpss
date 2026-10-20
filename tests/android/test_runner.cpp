// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include "tests/test_entry.h"
#include <android/log.h>
#include <jni.h>

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void * /*reserved*/)
{
    if (!mpss::initialize_android(vm))
    {
        __android_log_write(ANDROID_LOG_ERROR, "MPSS_TESTS", mpss::get_error().c_str());
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jint JNICALL Java_com_microsoft_mpss_tests_TestRunner_runAllTests(JNIEnv * /*env*/,
                                                                                       jclass /*test_runner*/)
{
    char executable_name[] = "mpss_tests";
    char *argv[] = {executable_name, nullptr};
    return mpss::tests::run_all_tests(1, argv);
}
