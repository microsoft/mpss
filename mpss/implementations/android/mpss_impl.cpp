// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/android/JNIHelper.h"
#include "mpss/implementations/android/JNIObject.h"
#include "mpss/implementations/android/android_keypair.h"
#include "mpss/implementations/android/android_utils.h"
#include "mpss/implementations/os_backend.h"
#include "mpss/utils/utilities.h"

using jni_class = mpss::impl::os::utils::JNIObj<jclass>;
using jni_string = mpss::impl::os::utils::JNIObj<jstring>;
using jni_object = mpss::impl::os::utils::JNIObj<jobject>;
using jni_bytearray = mpss::impl::os::utils::JNIObj<jbyteArray>;

namespace
{

constexpr const char *unknown_storage = "Unknown";
constexpr const char *software_storage = "Software";
constexpr const char *trusted_storage = "Trusted Environment";
constexpr const char *strongbox_storage = "StrongBox";
constexpr const char *unknown_secure_storage = "Unknown Secure";

void GetKeyProperties(std::string_view name, bool &hardware_backed, const char **storage_description)
{
    hardware_backed = false;
    *storage_description = nullptr;

    mpss::impl::os::JNIEnvGuard guard;
    jni_class km(guard.Env(), mpss::impl::os::utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class");
        return;
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "GetKeySecurityLevel", "(Ljava/lang/String;)I");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetKeySecurityLevel Java method");
        return;
    }

    const std::string keyNameStr(name);
    jni_string keyName(guard.Env(), guard->NewStringUTF(keyNameStr.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String");
        return;
    }

    const jint result = guard->CallStaticIntMethod(km.get(), mid, keyName.get());
    if (-1 == result)
    {
        mpss::utils::log_and_set_error("Error calling KeyManagement.GetKeySecurityLevel Java method");
        return;
    }

    switch (result)
    {
    case 0:
        hardware_backed = false;
        *storage_description = unknown_storage;
        return;
    case 1:
        hardware_backed = false;
        *storage_description = software_storage;
        return;
    case 2:
        hardware_backed = true;
        *storage_description = unknown_secure_storage;
        return;
    case 3:
        hardware_backed = true;
        *storage_description = trusted_storage;
        return;
    case 4:
        hardware_backed = true;
        *storage_description = strongbox_storage;
        return;
    default:
        mpss::utils::log_and_set_error("Unknown result from KeyManagement.GetKeySecurityLevel");
        return;
    }
}

} // namespace

namespace mpss::impl::os
{

using enum Algorithm;

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }

    mpss::utils::log_trace("Attempting to open key '{}' on Android backend.", name);

    JNIEnvGuard guard;
    jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    const std::string nameStr{name};
    jni_string keyName(guard.Env(), guard->NewStringUTF(nameStr.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not create key name Java string.");
        return nullptr;
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "OpenKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.OpenKey Java method.");
        return nullptr;
    }

    jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid, keyName.get()));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.OpenKey returned null.");
        return nullptr;
    }

    if (!utils::UnboxBoolean(guard.Env(), result.get()))
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
        return nullptr;
    }

    // Now we need the Algorithm.
    jmethodID mid_algo = guard->GetStaticMethodID(km.get(), "GetKeyAlgorithm",
                                                  "(Ljava/lang/String;)Lcom/microsoft/research/mpss/Algorithm;");
    if (nullptr == mid_algo)
    {
        mpss::utils::log_and_set_error("Failed to get KeyManagement.GetKeyAlgorithm method.");
        return nullptr;
    }

    jni_object algo_result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid_algo, keyName.get()));
    if (algo_result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.GetKeyAlgorithm returned null.");
        return nullptr;
    }

    jni_class algo_class(guard.Env(), guard->GetObjectClass(algo_result.get()));
    if (algo_class.is_null())
    {
        mpss::utils::log_and_set_error("Failed to get Java class for Algorithm.");
        return nullptr;
    }

    jmethodID nameMethod = guard->GetMethodID(algo_class.get(), "name", "()Ljava/lang/String;");
    if (nullptr == nameMethod)
    {
        mpss::utils::log_and_set_error("Could not get method id for Algorithm.name.");
        return nullptr;
    }

    jni_string algo_name(guard.Env(),
                         reinterpret_cast<jstring>(guard->CallObjectMethod(algo_result.get(), nameMethod)));
    if (algo_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not get name of enum Algorithm.");
        return nullptr;
    }

    const std::string algo_name_str = mpss::impl::os::utils::GetString(guard.Env(), algo_name.get());
    Algorithm algorithm = unsupported;

    if (algo_name_str == "secp256r1")
    {
        algorithm = ecdsa_secp256r1_sha256;
    }
    else if (algo_name_str == "secp384r1")
    {
        algorithm = ecdsa_secp384r1_sha384;
    }
    else if (algo_name_str == "secp521r1")
    {
        algorithm = ecdsa_secp521r1_sha512;
    }

    bool hardware_backed = false;
    const char *storage_description = nullptr;
    GetKeyProperties(name, hardware_backed, &storage_description);

    if (nullptr == storage_description)
    {
        // Error happened getting key properties. This is reported by GetKeyProperties, so we just return here.
        return nullptr;
    }

    // Finally, we can return the key.
    mpss::utils::log_trace("Key '{}' opened on Android with {} storage.", name, storage_description);
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description);
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm)
{
    if (name.empty())
    {
        mpss::utils::log_warn("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warn("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    // Check if the key already exists
    std::unique_ptr<KeyPair> existingKey = open_key(name);
    if (nullptr != existingKey)
    {
        mpss::utils::log_warn("Key '{}' already exists.", name);
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' with algorithm '{}' on Android backend.", name,
                           get_algorithm_info(algorithm).type_str);

    JNIEnvGuard guard;
    jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    jmethodID mid = guard->GetStaticMethodID(
        km.get(), "CreateKey", "(Ljava/lang/String;Lcom/microsoft/research/mpss/Algorithm;)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CreateKey Java method.");
        return nullptr;
    }

    const std::string keyNameStr(name);
    jni_string keyName(guard.Env(), guard->NewStringUTF(keyNameStr.c_str()));
    if (keyName.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String.");
        return nullptr;
    }

    jni_class algorithmClass(guard.Env(), guard->FindClass("com/microsoft/research/mpss/Algorithm"));
    if (algorithmClass.is_null())
    {
        mpss::utils::log_and_set_error("Could not get Algorithm Java class.");
        return nullptr;
    }

    jfieldID algoFieldId = nullptr;

    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        algoFieldId =
            guard->GetStaticFieldID(algorithmClass.get(), "secp256r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp384r1_sha384:
        algoFieldId =
            guard->GetStaticFieldID(algorithmClass.get(), "secp384r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    case ecdsa_secp521r1_sha512:
        algoFieldId =
            guard->GetStaticFieldID(algorithmClass.get(), "secp521r1", "Lcom/microsoft/research/mpss/Algorithm;");
        break;
    default:
        mpss::utils::log_warn("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (nullptr == algoFieldId)
    {
        mpss::utils::log_and_set_error("Could not find appropriate enum value for Algorithm.");
        return nullptr;
    }

    jni_object algorithmValue(guard.Env(), guard->GetStaticObjectField(algorithmClass.get(), algoFieldId));
    if (algorithmValue.is_null())
    {
        mpss::utils::log_and_set_error("Could not get object for Algorithm value.");
        return nullptr;
    }

    jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid, keyName.get(), algorithmValue.get()));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.CreateKey returned null.");
        return nullptr;
    }

    if (!utils::UnboxBoolean(guard.Env(), result.get()))
    {
        // Error happened in Java side.
        mpss::utils::log_and_set_error(mpss::impl::os::utils::GetError(guard.Env()));
        return nullptr;
    }

    bool hardware_backed = false;
    const char *storage_description = nullptr;
    GetKeyProperties(name, hardware_backed, &storage_description);

    if (nullptr == storage_description)
    {
        // Error happened getting key properties. This is reported by GetKeyProperties, so we just return here.
        return nullptr;
    }

    mpss::utils::log_trace("Key '{}' created on Android with {} storage.", name, storage_description);
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description);
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_warn("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_warn("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return false;
    }

    // Check hash length.
    if (!mpss::utils::check_exact_hash_size(hash, algorithm))
    {
        return false;
    }

    JNIEnvGuard guard;

    jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
    if (km.is_null())
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID mid = guard->GetStaticMethodID(km.get(), "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
    if (nullptr == mid)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray hash_arr(guard.Env(), utils::ToJByteArray(guard.Env(), hash));
    if (hash_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert hash to jbyte array.");
        return false;
    }

    jni_bytearray pk_arr(guard.Env(), utils::ToJByteArray(guard.Env(), public_key));
    if (pk_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert public key to jbyte array.");
        return false;
    }

    jni_bytearray sig_arr(guard.Env(), utils::ToJByteArray(guard.Env(), sig));
    if (sig_arr.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert signature to jbyte array.");
        return false;
    }

    jni_object result(guard.Env(),
                      guard->CallStaticObjectMethod(km.get(), mid, hash_arr.get(), sig_arr.get(), pk_arr.get()));
    if (result.is_null())
    {
        mpss::utils::log_and_set_error("KeyManagement.VerifySignature returned null.");
        return false;
    }

    const bool verified = utils::UnboxBoolean(guard.Env(), result.get());

    mpss::utils::log_trace("Verification using standalone signature verification {}.",
                           verified ? "succeeded" : "failed");
    return verified;
}

} // namespace mpss::impl::os
