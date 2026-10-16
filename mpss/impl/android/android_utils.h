// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <jni.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace mpss::impl::os::utils
{

/**
 * Clear a pending Java exception and report it through the MPSS error channel.
 * @param env Java environment
 * @param operation Operation that raised the exception
 * @return True if an exception was cleared
 */
bool check_and_clear_exception(JNIEnv *env, std::string_view operation);

/**
 * Convert a std::span of bytes to a Java byte array
 * @param env Java environment
 * @param bytes Span to convert
 * @return Java byte array
 */
jbyteArray to_jbyte_array(JNIEnv *env, std::span<const std::byte> bytes);

/**
 * Copy the contents of a Java byte array to a span of bytes
 * @param env Java environment
 * @param array Java byte array to copy
 * @param output Destination span where bytes are copied
 * @return Size of the Java byte array
 */
std::size_t copy_jbyte_array_to_span(JNIEnv *env, jbyteArray array, std::span<std::byte> output);

/**
 * Unbox a Java Boolean object into a C++ bool
 * @param env Java environment
 * @param boolean_obj Java boolean object to unbox
 * @return Value of the Java boolean object, or no value on failure
 */
std::optional<bool> unbox_boolean(JNIEnv *env, jobject boolean_obj);

std::optional<std::int64_t> unbox_long(JNIEnv *env, jobject long_obj);

/**
 * Consume the current KeyManagement error and report it with operation context.
 * @param env Java environment
 * @param operation Java operation that failed
 */
void report_java_error(JNIEnv *env, std::string_view operation);

/**
 * Convert a Java String into a std::string
 * @param env Java environment
 * @param str Java string to convert
 * @return Standard string
 */
std::string get_string(JNIEnv *env, jstring str);

} // namespace mpss::impl::os::utils
