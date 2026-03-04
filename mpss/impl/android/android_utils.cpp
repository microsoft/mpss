// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/android_utils.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os::utils
{

using jni_class = JNIObj<jclass>;
using jni_string = JNIObj<jstring>;

jclass GetKeyManagementClass(JNIEnv *env)
{
    return env->FindClass("com/microsoft/research/mpss/KeyManagement");
}

jbyteArray ToJByteArray(JNIEnv *env, std::span<const std::byte> bytes)
{
    jbyteArray array = env->NewByteArray(bytes.size());
    if (nullptr == array)
    {
        return nullptr;
    }

    env->SetByteArrayRegion(array,
                            /* start */ 0, bytes.size(), reinterpret_cast<const jbyte *>(bytes.data()));

    return array;
}

std::size_t CopyJByteArrayToSpan(JNIEnv *env, jbyteArray array, std::span<std::byte> output)
{
    const jsize len = env->GetArrayLength(array);
    if (output.size() < len)
    {
        mpss::utils::log_and_set_error("Output size is {} (expected {}).", output.size(), len);
        return 0;
    }

    env->GetByteArrayRegion(array,
                            /* start */ 0, len, reinterpret_cast<jbyte *>(output.data()));

    return len;
}

bool UnboxBoolean(JNIEnv *env, jobject booleanObj)
{
    if (nullptr == booleanObj)
    {
        return false;
    }

    jclass booleanClass = env->FindClass("java/lang/Boolean");
    if (nullptr == booleanClass)
    {
        return false;
    }

    jmethodID mid = env->GetMethodID(booleanClass, "booleanValue", "()Z");
    if (nullptr == mid)
    {
        return false;
    }

    return (JNI_TRUE == env->CallBooleanMethod(booleanObj, mid));
}

std::string GetError(JNIEnv *env)
{
    if (nullptr == env)
    {
        mpss::utils::log_and_set_error("env is null.");
        return {};
    }

    jni_class km(env, GetKeyManagementClass(env));
    if (km.is_null())
    {
        return "Could not get KeyManagement Java class.";
    }

    jmethodID mid = env->GetStaticMethodID(km.get(), "GetError", "()Ljava/lang/String;");
    if (nullptr == mid)
    {
        return "Could not find KeyManagement.GetError method.";
    }

    jni_string error(env, reinterpret_cast<jstring>(env->CallStaticObjectMethod(km.get(), mid)));
    if (error.is_null())
    {
        return "Could not get error string.";
    }

    std::string result = GetString(env, error.get());
    return result;
}

std::string GetString(JNIEnv *env, jstring str)
{
    if (nullptr == env)
    {
        mpss::utils::log_and_set_error("env is null.");
        return {};
    }

    const char *chars = env->GetStringUTFChars(str, /* isCopy */ nullptr);
    std::string result(chars);
    env->ReleaseStringUTFChars(str, chars);

    return result;
}

} // namespace mpss::impl::os::utils
