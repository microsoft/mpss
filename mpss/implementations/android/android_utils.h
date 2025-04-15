// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <jni.h>
#include <gsl/span>

namespace mpss::impl::utils {
    jclass GetKeyManagementClass(JNIEnv* env);

    jbyteArray ToJByteArray(JNIEnv* env, gsl::span<const std::byte> bytes);

    std::size_t CopyJByteArrayToSpan(JNIEnv* env, jbyteArray array, gsl::span<std::byte> output);

    bool UnboxBoolean(JNIEnv* env, jobject booleanObj);
}
