// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/impl/key_probe.h"
#include "mpss/impl/os_backend.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <optional>

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

void get_key_properties(std::string_view name, bool &hardware_backed, const char **storage_description)
{
    hardware_backed = false;
    *storage_description = nullptr;

    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class");
        return;
    }

    jmethodID method = mpss::impl::os::JNIHelper::method(mpss::impl::os::JNIHelper::JavaMethod::get_key_security_level);
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.GetKeySecurityLevel Java method");
        return;
    }

    const std::string key_name_str(name);
    jni_string key_name(env, env->NewStringUTF(key_name_str.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String");
        return;
    }

    const jint result = env->CallStaticIntMethod(key_management, method, key_name.get());
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.GetKeySecurityLevel"))
    {
        return;
    }
    if (-1 == result)
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.GetKeySecurityLevel");
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

namespace
{

using OpenKeyResult = KeyProbeResult<std::unique_ptr<KeyPair>>;

// Release the hold a successful open or create took on the cached key. Nothing else will: the hold
// is released by the key pair's destructor, and on these paths no key pair is ever constructed.
void release_cached_key(JNIEnv *env, jclass key_management, jstring key_name, std::uint64_t generation)
{
    jmethodID method = JNIHelper::method(JNIHelper::JavaMethod::close_key);
    if (nullptr == method)
    {
        return;
    }

    env->CallStaticVoidMethod(key_management, method, key_name, static_cast<jlong>(generation));
    static_cast<void>(utils::check_and_clear_exception(env, "calling KeyManagement.CloseKey"));
}

OpenKeyResult try_open_key(std::string_view name)
{
    mpss::utils::log_trace("Attempting to open key '{}' on Android backend.", name);

    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::string name_str{name};
    jni_string key_name(env, env->NewStringUTF(name_str.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not create key name Java string.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jmethodID method = JNIHelper::method(JNIHelper::JavaMethod::open_key);
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.OpenKey Java method.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, key_name.get()));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.OpenKey"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.OpenKey");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::optional<std::int64_t> opened = utils::unbox_long(env, result.get());
    if (!opened.has_value())
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (0 > opened.value())
    {
        return {.status = KeyProbeStatus::not_found, .value = nullptr};
    }
    const std::uint64_t generation = static_cast<std::uint64_t>(opened.value());

    // The open took a hold on the cached key so that another handle's close cannot evict it. Every
    // path from here that does not hand back a key pair has to release that hold, or the entry
    // outlives the handle that justified it.
    bool handed_to_caller = false;
    SCOPE_GUARD({
        if (!handed_to_caller)
        {
            release_cached_key(env, key_management, key_name.get(), generation);
        }
    });

    // Now we need the Algorithm.
    jmethodID mid_algo = JNIHelper::method(JNIHelper::JavaMethod::get_key_algorithm);
    if (nullptr == mid_algo)
    {
        mpss::utils::log_and_set_error("Failed to get KeyManagement.GetKeyAlgorithm method.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jni_object algo_result(env, env->CallStaticObjectMethod(key_management, mid_algo, key_name.get()));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.GetKeyAlgorithm"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (algo_result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.GetKeyAlgorithm");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jclass algorithm_class = JNIHelper::algorithm_class();
    if (nullptr == algorithm_class)
    {
        mpss::utils::log_and_set_error("Failed to get Java class for Algorithm.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jmethodID name_method = JNIHelper::method(JNIHelper::JavaMethod::algorithm_name);
    if (nullptr == name_method)
    {
        mpss::utils::log_and_set_error("Could not get method id for Algorithm.name.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    jni_string algo_name(env, reinterpret_cast<jstring>(env->CallObjectMethod(algo_result.get(), name_method)));
    if (utils::check_and_clear_exception(env, "calling Algorithm.name"))
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
    if (algo_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not get name of enum Algorithm.");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    const std::string algo_name_str = mpss::impl::os::utils::get_string(env, algo_name.get());
    if (algo_name_str.empty())
    {
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }
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
    if (unsupported == algorithm)
    {
        utils::report_java_error(env, "KeyManagement.GetKeyAlgorithm");
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    bool hardware_backed = false;
    const char *storage_description = nullptr;
    get_key_properties(name, hardware_backed, &storage_description);

    if (nullptr == storage_description)
    {
        // Error happened getting key properties. This is reported by get_key_properties, so we just return here.
        return {.status = KeyProbeStatus::operational_error, .value = nullptr};
    }

    // Finally, we can return the key.
    mpss::utils::log_trace("Key '{}' opened on Android with {} storage.", name, storage_description);
    handed_to_caller = true;
    return {.status = KeyProbeStatus::found,
            .value =
                std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description, generation)};
}

} // namespace

std::unique_ptr<KeyPair> open_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    OpenKeyResult result = try_open_key(name);
    if (KeyProbeStatus::not_found == result.status)
    {
        mpss::utils::log_debug("Key '{}' not found.", name);
    }

    return std::move(result.value);
}

bool delete_key(std::string_view name)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return false;
    }

    // The alias is addressed directly rather than through an opened key pair. A KeyStore alias is
    // unique within the application, so there is no ambiguity to resolve, and an entry whose key or
    // certificate cannot be read has to be clearable -- that is the state a caller most needs to
    // recover from, and it is exactly the one an open cannot reach.
    mpss::impl::os::JNIEnvGuard guard;
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

    const std::string name_str{name};
    jni_string key_name(env, env->NewStringUTF(name_str.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return false;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not create key name Java string.");
        return false;
    }

    jmethodID method = JNIHelper::method(JNIHelper::JavaMethod::delete_key_by_name);
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.DeleteKey Java method.");
        return false;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, key_name.get()));
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
        mpss::utils::log_and_set_error("Could not read the result of KeyManagement.DeleteKey.");
        return false;
    }
    if (!deleted.value())
    {
        utils::report_java_error(env, "KeyManagement.DeleteKey");
        return false;
    }

    return true;
}

std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm, KeyPolicy policy)
{
    if (name.empty())
    {
        mpss::utils::log_and_set_error("Key name cannot be empty.");
        return nullptr;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (KeyPolicy::none != policy)
    {
        mpss::utils::log_and_set_error("Android backend does not support the requested key policy.");
        return nullptr;
    }

    // Check if the key already exists. A probe that could not determine presence must not create, or an
    // existing key could be replaced.
    OpenKeyResult existing_key = try_open_key(name);
    if (KeyProbeStatus::operational_error == existing_key.status)
    {
        return nullptr;
    }
    if (KeyProbeStatus::found == existing_key.status)
    {
        mpss::utils::log_and_set_error("Key '{}' already exists.", name);
        return nullptr;
    }

    mpss::utils::log_trace("Creating key '{}' with algorithm '{}' on Android backend.", name,
                           get_algorithm_info(algorithm).type_str);

    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::log_and_set_error("Android JNI environment is unavailable.");
        return nullptr;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement Java class.");
        return nullptr;
    }

    jmethodID method = JNIHelper::method(JNIHelper::JavaMethod::create_key);
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.CreateKey Java method.");
        return nullptr;
    }

    const std::string key_name_str(name);
    jni_string key_name(env, env->NewStringUTF(key_name_str.c_str()));
    if (utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return nullptr;
    }
    if (key_name.is_null())
    {
        mpss::utils::log_and_set_error("Could not convert key name to Java String.");
        return nullptr;
    }

    jclass algorithm_class = JNIHelper::algorithm_class();
    if (nullptr == algorithm_class)
    {
        mpss::utils::log_and_set_error("Could not get Algorithm Java class.");
        return nullptr;
    }

    jfieldID algo_field_id = nullptr;

    switch (algorithm)
    {
    case ecdsa_secp256r1_sha256:
        algo_field_id = env->GetStaticFieldID(algorithm_class, "secp256r1", "Lcom/microsoft/mpss/Algorithm;");
        break;
    case ecdsa_secp384r1_sha384:
        algo_field_id = env->GetStaticFieldID(algorithm_class, "secp384r1", "Lcom/microsoft/mpss/Algorithm;");
        break;
    case ecdsa_secp521r1_sha512:
        algo_field_id = env->GetStaticFieldID(algorithm_class, "secp521r1", "Lcom/microsoft/mpss/Algorithm;");
        break;
    default:
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return nullptr;
    }

    if (utils::check_and_clear_exception(env, "resolving an Algorithm enum value"))
    {
        return nullptr;
    }
    if (nullptr == algo_field_id)
    {
        mpss::utils::log_and_set_error("Could not find appropriate enum value for Algorithm.");
        return nullptr;
    }

    jni_object algorithm_value(env, env->GetStaticObjectField(algorithm_class, algo_field_id));
    if (utils::check_and_clear_exception(env, "getting an Algorithm enum value"))
    {
        return nullptr;
    }
    if (algorithm_value.is_null())
    {
        mpss::utils::log_and_set_error("Could not get object for Algorithm value.");
        return nullptr;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, key_name.get(), algorithm_value.get()));
    if (utils::check_and_clear_exception(env, "calling KeyManagement.CreateKey"))
    {
        return nullptr;
    }
    if (result.is_null())
    {
        utils::report_java_error(env, "KeyManagement.CreateKey");
        return nullptr;
    }

    const std::optional<std::int64_t> created = utils::unbox_long(env, result.get());
    if (!created.has_value() || 0 > created.value())
    {
        utils::report_java_error(env, "KeyManagement.CreateKey");
        return nullptr;
    }
    const std::uint64_t generation = static_cast<std::uint64_t>(created.value());

    // Creation took a hold on the cached key, released by the key pair's destructor. A path that
    // returns without one has to release it here instead.
    bool handed_to_caller = false;
    SCOPE_GUARD({
        if (!handed_to_caller)
        {
            release_cached_key(env, key_management, key_name.get(), generation);
        }
    });

    bool hardware_backed = false;
    const char *storage_description = nullptr;
    get_key_properties(name, hardware_backed, &storage_description);

    if (nullptr == storage_description)
    {
        // Error happened getting key properties. This is reported by get_key_properties, so we just return here.
        return nullptr;
    }

    mpss::utils::log_trace("Key '{}' created on Android with {} storage.", name, storage_description);
    handed_to_caller = true;
    return std::make_unique<AndroidKeyPair>(algorithm, name, hardware_backed, storage_description, generation);
}

bool verify(std::span<const std::byte> hash, std::span<const std::byte> public_key, Algorithm algorithm,
            std::span<const std::byte> sig)
{
    if (hash.empty() || public_key.empty() || sig.empty())
    {
        mpss::utils::log_and_set_error("Hash, public key, and signature cannot be empty.");
        return false;
    }

    if (unsupported == algorithm)
    {
        mpss::utils::log_and_set_error("Unsupported algorithm '{}'.", get_algorithm_info(algorithm).type_str);
        return false;
    }

    // Check hash length.
    if (!mpss::utils::check_exact_hash_size(hash, algorithm))
    {
        return false;
    }

    // The verification algorithm is inferred from the public key length on the Java side, so require
    // an exact length match here to keep the public key bound to the requested algorithm.
    const std::size_t expected_pk_size = mpss::utils::get_public_key_size(algorithm);
    if (public_key.size() != expected_pk_size)
    {
        mpss::utils::log_and_set_error("Public key length {} does not match algorithm '{}' (expected {}).",
                                       public_key.size(), get_algorithm_info(algorithm).type_str, expected_pk_size);
        return false;
    }

    mpss::impl::os::JNIEnvGuard guard;
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

    jmethodID method = JNIHelper::method(JNIHelper::JavaMethod::verify_standalone_signature);
    if (nullptr == method)
    {
        mpss::utils::log_and_set_error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray hash_arr(env, utils::to_jbyte_array(env, hash));
    if (hash_arr.is_null())
    {
        return false;
    }

    jni_bytearray pk_arr(env, utils::to_jbyte_array(env, public_key));
    if (pk_arr.is_null())
    {
        return false;
    }

    jni_bytearray sig_arr(env, utils::to_jbyte_array(env, sig));
    if (sig_arr.is_null())
    {
        return false;
    }

    jni_object result(env,
                      env->CallStaticObjectMethod(key_management, method, hash_arr.get(), sig_arr.get(), pk_arr.get()));
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

    mpss::utils::log_trace("Verification using standalone signature verification {}.",
                           verified.value() ? "succeeded" : "failed");
    return verified.value();
}

} // namespace mpss::impl::os
