// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "android_utils.h"
#include "../../utilities.h"

namespace mpss::impl::utils {
    jclass GetKeyManagementClass(JNIEnv* env) {
        return env->FindClass("com/microsoft/research/mpss/KeyManagement");
    }

    jbyteArray ToJByteArray(JNIEnv* env, gsl::span<const std::byte> bytes) {
        jbyteArray array = env->NewByteArray(bytes.size());
        if (array == nullptr) {
            return nullptr;
        }

        env->SetByteArrayRegion(
                array,
                /* start */ 0,
                bytes.size(),
                reinterpret_cast<const jbyte*>(bytes.data()));

        return array;
    }

    std::size_t CopyJByteArrayToSpan(JNIEnv* env, jbyteArray array, gsl::span<std::byte> output) {
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

    bool UnboxBoolean(JNIEnv* env, jobject booleanObj) {
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
}
