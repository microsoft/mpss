// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <jni.h>
#include <type_traits>

namespace mpss::impl::utils {
    // Allowed JNI types
    template <typename T>
    struct IsAllowedType : std::false_type {};

    template <>
    struct IsAllowedType<jobject> : std::true_type {};

    template <>
    struct IsAllowedType<jstring> : std::true_type {};

    template <>
    struct IsAllowedType<jclass> : std::true_type {};

    template <>
    struct IsAllowedType<jbyteArray> : std::true_type {};

    template <typename T>
    class JNIObj {
        static_assert(IsAllowedType<T>::value, "Type not allowed.");

    public:
        using type = T;
        JNIObj(JNIEnv *env, T localRef) : env_(env), ref_(localRef)
        {}

        ~JNIObj()
        {
            if (nullptr != ref_) {
                env_->DeleteLocalRef(ref_);
                ref_ = nullptr;
            }
        }

        T get()
        {
            return ref_;
        }
        T operator->()
        {
            return ref_;
        }

        bool is_null() const
        {
            return nullptr == ref_;
        }

    private:
        JNIEnv *env_;
        T ref_;
    };
} // namespace mpss::impl::utils
