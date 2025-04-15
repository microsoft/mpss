// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <jni.h>
#include <gsl/span>

namespace mpss::impl::utils {
    /**
     * Get KeyManagement java class
     * @param env Java environment
     * @return KeyManagement java class
     */
    jclass GetKeyManagementClass(JNIEnv* env);

    /**
     * Convert a gsl::span of bytes to a Java byte array
     * @param env Java environment
     * @param bytes Span to convert
     * @return Java byte array
     */
    jbyteArray ToJByteArray(JNIEnv* env, gsl::span<const std::byte> bytes);

    /**
     * Copy the contents of a Java byte array to a span of bytes
     * @param env Java environment
     * @param array Java byte array to copy
     * @param output Destination span where bytes are copied
     * @return Size of the Java byte array
     */
    std::size_t CopyJByteArrayToSpan(JNIEnv* env, jbyteArray array, gsl::span<std::byte> output);

    /**
     * Unbox a Java Boolean object into a C++ bool
     * @param env Java environment
     * @param booleanObj Java boolean object to unbox
     * @return Value of the Java boolean object
     */
    bool UnboxBoolean(JNIEnv* env, jobject booleanObj);

    /**
     * Get value of KeyManagement.GetError
     * @param env Java environment
     * @return Last error in KeyManagement.GetError
     */
    std::string GetError(JNIEnv* env);

    /**
     * Convert a Java String into a std::string
     * @param env Java environment
     * @param str Java string to convert
     * @return Standard string
     */
    std::string GetString(JNIEnv* env, jstring str);
}
