// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

using jni_string = utils::JNIObj<jstring>;
using jni_object = utils::JNIObj<jobject>;
using jni_bytearray = utils::JNIObj<jbyteArray>;

bool AndroidKeyPair::do_delete_key()
{
    mpss::utils::log_trace("Deleting Android key '{}'.", key_name_);

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return false;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "DeleteKey", "(Ljava/lang/String;J)Ljava/lang/Boolean;");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.DeleteKey"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.DeleteKey Java method.");
        return false;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return false;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return false;
    }

    jni_object result(
        env, env->CallStaticObjectMethod(key_management, method, key_name.get(), static_cast<jlong>(generation_)));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.DeleteKey"))
    {
        return false;
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.DeleteKey");
        return false;
    }

    const std::optional<bool> deleted = utils::unbox_boolean(env, result.get());
    if (!deleted.has_value())
    {
        return false;
    }
    if (!deleted.value())
    {
        utils::report_java_error(env, "KeyManagement.DeleteKey");
        return false;
    }

    mpss::utils::log_trace("Android key '{}' deleted.", key_name_);
    return true;
}

std::size_t AndroidKeyPair::do_sign_hash(std::span<const std::byte> hash, std::span<std::byte> sig) const
{
    mpss::utils::log_trace("Signing hash with Android key '{}', hash size {}.", key_name_, hash.size());

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return 0;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return 0;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "SignHash", "(Ljava/lang/String;[BJ)[B");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.SignHash"))
    {
        return 0;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.SignHash method.");
        return 0;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return 0;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return 0;
    }

    jni_bytearray hash_arr(env, utils::to_jbyte_array(env, hash));
    if (hash_arr.is_null())
    {
        return 0;
    }

    jni_bytearray result(env,
                         reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
                             key_management, method, key_name.get(), hash_arr.get(), static_cast<jlong>(generation_))));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.SignHash"))
    {
        return 0;
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.SignHash");
        return 0;
    }

    std::size_t sig_size = utils::copy_jbyte_array_to_span(env, result.get(), sig);
    if (0 != sig_size)
    {
        mpss::utils::log_trace("Android sign produced {} byte signature.", sig_size);
    }

    return sig_size;
}

bool AndroidKeyPair::do_verify(std::span<const std::byte> hash, std::span<const std::byte> sig) const
{
    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return false;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID method =
        env->GetStaticMethodID(key_management, "VerifySignature", "(Ljava/lang/String;[B[BJ)Ljava/lang/Boolean;");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature method.");
        return false;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return false;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return false;
    }

    jni_bytearray hash_arr(env, utils::to_jbyte_array(env, hash));
    if (hash_arr.is_null())
    {
        return false;
    }

    jni_bytearray sig_arr(env, utils::to_jbyte_array(env, sig));
    if (sig_arr.is_null())
    {
        return false;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, key_name.get(), hash_arr.get(),
                                                       sig_arr.get(), static_cast<jlong>(generation_)));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.VerifySignature");
        return false;
    }

    const std::optional<bool> verified = utils::unbox_boolean(env, result.get());
    if (!verified.has_value())
    {
        return false;
    }

    // This should not fail at this point unless the signature is invalid. The caller already validated inputs.
    return verified.value();
}

std::size_t AndroidKeyPair::do_extract_key(std::span<std::byte> public_key) const
{
    mpss::utils::log_trace("Extracting public key from Android key '{}'.", key_name_);

    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return 0;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return 0;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "GetPublicKey", "(Ljava/lang/String;J)[B");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.GetPublicKey"))
    {
        return 0;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetPublicKey method.");
        return 0;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return 0;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return 0;
    }

    jni_bytearray result(env, reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
                                  key_management, method, key_name.get(), static_cast<jlong>(generation_))));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.GetPublicKey"))
    {
        return 0;
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.GetPublicKey");
        return 0;
    }

    std::size_t key_size = utils::copy_jbyte_array_to_span(env, result.get(), public_key);
    return key_size;
}

void AndroidKeyPair::do_release_key()
{
    close_key();
}

void AndroidKeyPair::close_key()
{
    JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "CloseKey", "(Ljava/lang/String;J)V");
    if (utils::check_and_clear_exception(env, "resolving KeyManagement.CloseKey"))
    {
        return;
    }
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CloseKey method.");
        return;
    }

    jni_string key_name(env, env->NewStringUTF(key_name_.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java string.");
        return;
    }

    env->CallStaticVoidMethod(key_management, method, key_name.get(), static_cast<jlong>(generation_));
    static_cast<void>(utils::check_and_clear_exception(env, "calling KeyManagement.CloseKey"));
}

} // namespace mpss::impl::os
