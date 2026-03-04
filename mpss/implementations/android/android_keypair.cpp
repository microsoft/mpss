// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/android/android_keypair.h"
#include "mpss/implementations/android/JNIObject.h"
#include "mpss/implementations/android/android_utils.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

using jni_class = utils::JNIObj<jclass>;
using jni_string = utils::JNIObj<jstring>;
using jni_object = utils::JNIObj<jobject>;
using jni_bytearray = utils::JNIObj<jbyteArray>;

bool AndroidKeyPair::delete_key()
{
    mpss::utils::log_trace("Deleting Android key '{}'.", key_name_);
    jni_class km(env(), utils::GetKeyManagementClass(env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID mi = env()->GetStaticMethodID(km.get(), "DeleteKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (nullptr == mi)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.DeleteKey Java method.");
        return false;
    }

    jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return false;
    }

    jni_object result(env(), env()->CallStaticObjectMethod(km.get(), mi, keyName.get()));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.DeleteKey returned null.");
        return false;
    }

    if (!utils::UnboxBoolean(env(), result.get()))
    {
        mpss::utils::log_and_set_error(utils::GetError(env()));
        return false;
    }

    mpss::utils::log_trace("Android key '{}' deleted.", key_name_);
    return true;
}

std::size_t AndroidKeyPair::sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    if (sig.empty())
    {
        // If the signature buffer is empty, we want to return the size of the signature.
        return mpss::utils::get_max_signature_size(algorithm());
    }

    mpss::utils::log_trace("Signing hash with Android key '{}', hash size {}.", key_name_, hash.size());

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return 0;
    }
    if (!mpss::utils::check_sufficient_signature_buffer_size(sig, algorithm()))
    {
        return 0;
    }

    jni_class km(env(), utils::GetKeyManagementClass(env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return 0;
    }

    jmethodID mid = env()->GetStaticMethodID(km.get(), "SignHash", "(Ljava/lang/String;[B)[B");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.SignHash method.");
        return 0;
    }

    jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return 0;
    }

    jni_bytearray hash_arr(env(), utils::ToJByteArray(env(), hash));
    if (hash_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert hash to jbyte array.");
        return 0;
    }

    jni_bytearray result(env(), reinterpret_cast<jbyteArray>(
                                    env()->CallStaticObjectMethod(km.get(), mid, keyName.get(), hash_arr.get())));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.SignHash returned null.");
        return 0;
    }

    std::size_t sig_size = utils::CopyJByteArrayToSpan(env(), result.get(), sig);
    if (0 == sig_size)
    {
        // Update error.
        mpss::utils::log_and_set_error(utils::GetError(env()));
    }
    else
    {
        mpss::utils::log_trace("Android sign produced {} byte signature.", sig_size);
    }

    return sig_size;
}

bool AndroidKeyPair::verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    if (hash.empty() || sig.empty())
    {
        mpss::utils::log_warning("Nothing to verify.");
        return false;
    }

    if (!mpss::utils::check_exact_hash_size(hash, algorithm()))
    {
        return false;
    }

    jni_class km(env(), utils::GetKeyManagementClass(env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID mid =
        env()->GetStaticMethodID(km.get(), "VerifySignature", "(Ljava/lang/String;[B[B)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature method.");
        return false;
    }

    jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return false;
    }

    jni_bytearray hash_arr(env(), utils::ToJByteArray(env(), hash));
    if (hash_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert hash to jbyte array.");
        return false;
    }

    jni_bytearray sig_arr(env(), utils::ToJByteArray(env(), sig));
    if (sig_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert sig to jbyte array.");
        return false;
    }

    jni_object result(env(),
                      env()->CallStaticObjectMethod(km.get(), mid, keyName.get(), hash_arr.get(), sig_arr.get()));
    const bool verified = utils::UnboxBoolean(env(), result.get());

    // This should not fail at this point unless the signature is invalid. The caller already validated inputs.
    return verified;
}

std::size_t AndroidKeyPair::extract_key(std::span<std::byte> public_key) const
{
    if (public_key.empty())
    {
        return mpss::utils::get_public_key_size(algorithm());
    }
    else if (!mpss::utils::check_sufficient_public_key_buffer_size(public_key, algorithm()))
    {
        return 0;
    }

    mpss::utils::log_trace("Extracting public key from Android key '{}'.", key_name_);

    jni_class km(env(), utils::GetKeyManagementClass(env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return 0;
    }

    jmethodID mid = env()->GetStaticMethodID(km.get(), "GetPublicKey", "(Ljava/lang/String;)[B");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetPublicKey method.");
        return 0;
    }

    jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return 0;
    }

    jni_bytearray result(env(),
                         reinterpret_cast<jbyteArray>(env()->CallStaticObjectMethod(km.get(), mid, keyName.get())));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.GetPublicKey returned null.");
        return 0;
    }

    std::size_t key_size = utils::CopyJByteArrayToSpan(env(), result.get(), public_key);
    if (0 == key_size)
    {
        // This should not fail at this point. The caller already validated inputs.
        mpss::utils::log_and_set_error(utils::GetError(env()));
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
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return;
    }

    jmethodID mid = env()->GetStaticMethodID(km.get(), "CloseKey", "(Ljava/lang/String;)V");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CloseKey method.");
        return;
    }

    jni_string keyName(env(), env()->NewStringUTF(key_name_.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return;
    }

    env()->CallStaticVoidMethod(km.get(), mid, keyName.get());
}

} // namespace mpss::impl::os
