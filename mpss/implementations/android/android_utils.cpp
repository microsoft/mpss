// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"
#include "android_utils.h"
#include "JNIObject.h"

namespace mpss::impl::utils {
    using jni_class = JNIObj<jclass>;
    using jni_string = JNIObj<jstring>;

    jclass GetKeyManagementClass(JNIEnv *env)
    {
        return env->FindClass("com/microsoft/research/mpss/KeyManagement");
    }

    jbyteArray ToJByteArray(JNIEnv *env, gsl::span<const std::byte> bytes)
    {
        jbyteArray array = env->NewByteArray(bytes.size());
        if (array == nullptr) {
            return nullptr;
        }

        env->SetByteArrayRegion(
            array,
            /* start */ 0,
            bytes.size(),
            reinterpret_cast<const jbyte *>(bytes.data()));

        return array;
    }

    std::size_t CopyJByteArrayToSpan(JNIEnv *env, jbyteArray array, gsl::span<std::byte> output)
    {
        jsize len = env->GetArrayLength(array);
        if (output.size() < len) {
            std::stringstream ss;
            ss << "Output size is " << output.size() << ", needs to be " << len;
            mpss::utils::set_error(ss.str());
            return 0;
        }

        env->GetByteArrayRegion(
            array,
            /* start */ 0,
            len,
            reinterpret_cast<jbyte *>(output.data()));

        return len;
    }

    bool UnboxBoolean(JNIEnv *env, jobject booleanObj)
    {
        if (nullptr == booleanObj) {
            return false;
        }

        jclass booleanClass = env->FindClass("java/lang/Boolean");
        if (nullptr == booleanClass) {
            return false;
        }

        jmethodID mid = env->GetMethodID(booleanClass, "booleanValue", "()Z");
        if (nullptr == mid) {
            return false;
        }

        return (JNI_TRUE == env->CallBooleanMethod(booleanObj, mid));
    }

    std::string GetError(JNIEnv *env)
    {
        if (nullptr == env) {
            throw std::invalid_argument("env is null");
        }

        jni_class km(env, GetKeyManagementClass(env));
        if (km.is_null()) {
            return "Could not get KeyManagement java class";
        }

        jmethodID mid = env->GetStaticMethodID(km.get(), "GetError", "()Ljava/lang/String;");
        if (nullptr == mid) {
            return "Could not find KeyManagement.GetError method";
        }

        jni_string error(
            env, reinterpret_cast<jstring>(env->CallStaticObjectMethod(km.get(), mid)));
        if (error.is_null()) {
            return "Could not get error string";
        }

        std::string result = mpss::impl::utils::GetString(env, error.get());
        return result;
    }

    std::string GetString(JNIEnv *env, jstring str)
    {
        if (nullptr == env) {
            throw std::invalid_argument("env is null");
        }

        const char *chars = env->GetStringUTFChars(str, /* isCopy */ nullptr);
        std::string result(chars);
        env->ReleaseStringUTFChars(str, chars);

        return result;
    }
} // namespace mpss::impl::utils
