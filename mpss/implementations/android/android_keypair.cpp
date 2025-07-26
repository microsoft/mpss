// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/utils/utilities.h"
#include "android_keypair.h"
#include "JNIObject.h"
#include "android_utils.h"

namespace mpss::impl {
    using jni_class = utils::JNIObj<jclass>;
    using jni_string = utils::JNIObj<jstring>;
    using jni_object = utils::JNIObj<jobject>;
    using jni_bytearray = utils::JNIObj<jbyteArray>;

    bool AndroidKeyPair::delete_key()
    {
        jni_class km(env(), utils::GetKeyManagementClass(env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement Java class");
            return false;
        }

        jmethodID mi = env()->GetStaticMethodID(km.get(), "DeleteKey", "(Ljava/lang/String;)V");
        if (nullptr == mi) {
            mpss::utils::set_error("Could not get KeyManagement.DeleteKey Java method");
            return false;
        }

        jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not convert key name to Java string");
            return false;
        }

        env()->CallStaticVoidMethod(km.get(), mi, keyName.get());

        return true;
    }

    std::size_t AndroidKeyPair::sign_hash(gsl::span<const std::byte> hash, gsl::span<std::byte> sig) const
    {
        if (!mpss::utils::check_hash_length(hash, algorithm())) {
            mpss::utils::set_error("Invalid hash length for algorithm");
            return 0;
        }

        jni_class km(env(), utils::GetKeyManagementClass(env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement Java class");
            return 0;
        }

        jmethodID mid = env()->GetStaticMethodID(km.get(), "SignHash", "(Ljava/lang/String;[B)[B");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.SignHash method");
            return 0;
        }

        jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not convert key name to Java string");
            return 0;
        }

        jni_bytearray hash_arr(env(), utils::ToJByteArray(env(), hash));
        if (hash_arr.is_null()) {
            mpss::utils::set_error("Could not convert hash to jbyte array");
            return 0;
        }

        jni_bytearray result(
            env(),
            reinterpret_cast<jbyteArray>(env()->CallStaticObjectMethod(km.get(), mid, keyName.get(), hash_arr.get())));
        if (result.is_null()) {
            mpss::utils::set_error("KeyManagement.SignHash returned null");
            return 0;
        }

        std::size_t sig_size = utils::CopyJByteArrayToSpan(env(), result.get(), sig);
        if (sig_size == 0) {
            // Update error
            mpss::utils::set_error(mpss::impl::utils::GetError(env()));
        }

        return sig_size;
    }

    bool AndroidKeyPair::verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> sig) const
    {
        jni_class km(env(), utils::GetKeyManagementClass(env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement Java class");
            return false;
        }

        jmethodID mid =
            env()->GetStaticMethodID(km.get(), "VerifySignature", "(Ljava/lang/String;[B[B)Ljava/lang/Boolean;");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.VerifySignature method");
            return false;
        }

        jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not convert key name to Java string");
            return false;
        }

        jni_bytearray hash_arr(env(), utils::ToJByteArray(env(), hash));
        if (hash_arr.is_null()) {
            mpss::utils::set_error("Could not convert hash to jbyte array");
            return false;
        }

        jni_bytearray sig_arr(env(), utils::ToJByteArray(env(), sig));
        if (sig_arr.is_null()) {
            mpss::utils::set_error(("Could not convert sig to jbyte array"));
            return false;
        }

        jni_object result(
            env(), env()->CallStaticObjectMethod(km.get(), mid, keyName.get(), hash_arr.get(), sig_arr.get()));
        bool verified = utils::UnboxBoolean(env(), result.get());

        if (!verified) {
            // Update error information
            mpss::utils::set_error(mpss::impl::utils::GetError(env()));
        }

        return verified;
    }

    std::size_t AndroidKeyPair::extract_key(gsl::span<std::byte> public_key) const
    {
        jni_class km(env(), utils::GetKeyManagementClass(env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement java class");
            return 0;
        }

        jmethodID mid = env()->GetStaticMethodID(km.get(), "GetPublicKey", "(Ljava/lang/String;)[B");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.GetPublicKey method");
            return false;
        }

        jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not convert key name to Java string");
            return false;
        }

        jni_bytearray result(
            env(), reinterpret_cast<jbyteArray>(env()->CallStaticObjectMethod(km.get(), mid, keyName.get())));
        if (result.is_null()) {
            mpss::utils::set_error("KeyManagement.GetPublicKey returned null");
            return false;
        }

        std::size_t key_size = utils::CopyJByteArrayToSpan(env(), result.get(), public_key);
        if (key_size == 0) {
            // Update error information
            mpss::utils::set_error(mpss::impl::utils::GetError(env()));
        }

        return key_size;
    }

    void AndroidKeyPair::release_key() noexcept
    {
        close_key();
    }

    void AndroidKeyPair::close_key()
    {
        jni_class km(env(), utils::GetKeyManagementClass(env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement java class");
            return;
        }

        jmethodID mid = env()->GetStaticMethodID(km.get(), "CloseKey", "(Ljava/lang/String;)V");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.CloseKey method");
            return;
        }

        jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not convert key name to Java string");
            return;
        }

        env()->CallStaticVoidMethod(km.get(), mid, keyName.get());
    }
} // namespace mpss::impl
