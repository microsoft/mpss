// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/log.h"
#include "mpss/mpss.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <array>
#include <cstddef>
#include <future>
#include <gtest/gtest.h>
#include <latch>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace mpss::tests
{

namespace
{

using jni_bytearray = mpss::impl::os::utils::JNIObj<jbyteArray>;
using jni_object = mpss::impl::os::utils::JNIObj<jobject>;
using jni_string = mpss::impl::os::utils::JNIObj<jstring>;

std::vector<std::byte> java_sign_hash(std::string_view key_name, std::span<const std::byte> hash)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::GetLogger()->error("Could not get JNI environment.");
        return {};
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::GetLogger()->error("Could not get KeyManagement Java class.");
        return {};
    }

    jmethodID method = env->GetStaticMethodID(key_management, "SignHash", "(Ljava/lang/String;[B)[B");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.SignHash"))
    {
        return {};
    }
    if (nullptr == method)
    {
        mpss::GetLogger()->error("Could not get KeyManagement.SignHash Java method.");
        return {};
    }

    const std::string key_name_string{key_name};
    jni_string java_key_name(env, env->NewStringUTF(key_name_string.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return {};
    }
    jni_bytearray java_hash(env, mpss::impl::os::utils::to_jbyte_array(env, hash));
    if (java_key_name.is_null() || java_hash.is_null())
    {
        mpss::GetLogger()->error("Could not convert standalone-signing inputs to Java.");
        return {};
    }

    jni_bytearray java_signature(env, reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
                                          key_management, method, java_key_name.get(), java_hash.get())));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.SignHash"))
    {
        return {};
    }
    if (java_signature.is_null())
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.SignHash");
        mpss::GetLogger()->error("{}", mpss::get_error());
        return {};
    }

    const jsize signature_size = env->GetArrayLength(java_signature.get());
    if (mpss::impl::os::utils::check_and_clear_exception(env, "getting a Java signature length"))
    {
        return {};
    }
    if (0 >= signature_size)
    {
        mpss::GetLogger()->error("KeyManagement.SignHash returned an empty signature.");
        return {};
    }

    std::vector<std::byte> signature(static_cast<std::size_t>(signature_size));
    const std::size_t copied = mpss::impl::os::utils::copy_jbyte_array_to_span(env, java_signature.get(), signature);
    if (signature.size() != copied)
    {
        return {};
    }
    return signature;
}

bool java_verify_signature(std::span<const std::byte> hash, std::span<const std::byte> public_key,
                           std::span<const std::byte> signature)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::GetLogger()->error("Could not get JNI environment.");
        return false;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::GetLogger()->error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::GetLogger()->error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray java_hash(env, mpss::impl::os::utils::to_jbyte_array(env, hash));
    jni_bytearray java_signature(env, mpss::impl::os::utils::to_jbyte_array(env, signature));
    jni_bytearray java_public_key(env, mpss::impl::os::utils::to_jbyte_array(env, public_key));
    if (java_hash.is_null() || java_signature.is_null() || java_public_key.is_null())
    {
        mpss::GetLogger()->error("Could not convert standalone-verification inputs to Java.");
        return false;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, java_hash.get(), java_signature.get(),
                                                       java_public_key.get()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (result.is_null())
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.VerifySignature");
        mpss::GetLogger()->error("{}", mpss::get_error());
        return false;
    }

    const std::optional<bool> verified = mpss::impl::os::utils::unbox_boolean(env, result.get());
    return verified.value_or(false);
}

std::optional<bool> java_key_operation(std::string_view operation, std::string_view key_name)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::set_error("Could not get JNI environment.");
        return std::nullopt;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::set_error("Could not get KeyManagement Java class.");
        return std::nullopt;
    }

    const std::string operation_string{operation};
    jmethodID method =
        env->GetStaticMethodID(key_management, operation_string.c_str(), "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement operation"))
    {
        return std::nullopt;
    }
    if (nullptr == method)
    {
        mpss::utils::set_error("Could not get KeyManagement Java method.");
        return std::nullopt;
    }

    const std::string key_name_string{key_name};
    jni_string java_key_name(env, env->NewStringUTF(key_name_string.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return std::nullopt;
    }
    if (java_key_name.is_null())
    {
        mpss::utils::set_error("Could not convert key name to Java String.");
        return std::nullopt;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, java_key_name.get()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement operation"))
    {
        return std::nullopt;
    }
    if (result.is_null())
    {
        const std::string operation_name = "KeyManagement." + operation_string;
        mpss::impl::os::utils::report_java_error(env, operation_name);
        return std::nullopt;
    }

    return mpss::impl::os::utils::unbox_boolean(env, result.get());
}

// OpenKey and CreateKey report the cache generation their hold was taken on, so they return a
// Long rather than a Boolean. A negative value means the key does not exist.
std::optional<std::int64_t> java_open_key(std::string_view key_name)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::set_error("Android JNI environment is unavailable.");
        return std::nullopt;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::set_error("Could not get KeyManagement Java class.");
        return std::nullopt;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "OpenKey", "(Ljava/lang/String;)Ljava/lang/Long;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.OpenKey") || nullptr == method)
    {
        mpss::utils::set_error("Could not get KeyManagement.OpenKey Java method.");
        return std::nullopt;
    }

    const std::string key_name_string{key_name};
    jni_string java_key_name(env, env->NewStringUTF(key_name_string.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string") ||
        java_key_name.is_null())
    {
        mpss::utils::set_error("Could not convert key name to Java String.");
        return std::nullopt;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, java_key_name.get()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.OpenKey"))
    {
        return std::nullopt;
    }
    if (result.is_null())
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.OpenKey");
        return std::nullopt;
    }

    return mpss::impl::os::utils::unbox_long(env, result.get());
}

std::optional<std::int64_t> java_create_key(std::string_view key_name, mpss::Algorithm algorithm)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::set_error("Could not get JNI environment.");
        return std::nullopt;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::set_error("Could not get KeyManagement Java class.");
        return std::nullopt;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "CreateKey",
                                              "(Ljava/lang/String;Lcom/microsoft/mpss/Algorithm;)Ljava/lang/Long;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.CreateKey"))
    {
        return std::nullopt;
    }
    if (nullptr == method)
    {
        mpss::utils::set_error("Could not get KeyManagement.CreateKey Java method.");
        return std::nullopt;
    }

    jclass algorithm_class = mpss::impl::os::JNIHelper::algorithm_class();
    if (nullptr == algorithm_class)
    {
        mpss::utils::set_error("Could not get Algorithm Java class.");
        return std::nullopt;
    }

    const char *algorithm_field = nullptr;
    switch (algorithm)
    {
    case mpss::Algorithm::ecdsa_secp256r1_sha256:
        algorithm_field = "secp256r1";
        break;
    case mpss::Algorithm::ecdsa_secp384r1_sha384:
        algorithm_field = "secp384r1";
        break;
    case mpss::Algorithm::ecdsa_secp521r1_sha512:
        algorithm_field = "secp521r1";
        break;
    default:
        mpss::utils::set_error("Unsupported algorithm.");
        return std::nullopt;
    }

    jfieldID algorithm_field_id =
        env->GetStaticFieldID(algorithm_class, algorithm_field, "Lcom/microsoft/mpss/Algorithm;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving an Algorithm enum value"))
    {
        return std::nullopt;
    }
    if (nullptr == algorithm_field_id)
    {
        mpss::utils::set_error("Could not find appropriate enum value for Algorithm.");
        return std::nullopt;
    }

    jni_object algorithm_value(env, env->GetStaticObjectField(algorithm_class, algorithm_field_id));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "getting an Algorithm enum value"))
    {
        return std::nullopt;
    }
    if (algorithm_value.is_null())
    {
        mpss::utils::set_error("Could not get object for Algorithm value.");
        return std::nullopt;
    }

    const std::string key_name_string{key_name};
    jni_string java_key_name(env, env->NewStringUTF(key_name_string.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return std::nullopt;
    }
    if (java_key_name.is_null())
    {
        mpss::utils::set_error("Could not convert key name to Java String.");
        return std::nullopt;
    }

    jni_object result(env,
                      env->CallStaticObjectMethod(key_management, method, java_key_name.get(), algorithm_value.get()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.CreateKey"))
    {
        return std::nullopt;
    }
    if (result.is_null())
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.CreateKey");
        return std::nullopt;
    }

    return mpss::impl::os::utils::unbox_long(env, result.get());
}

} // namespace

TEST(AndroidSecurityTest, JavaCreateKeyRefusesToReplaceExistingKey)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Algorithm not supported by current backend";
    }

    const std::string key_name = "test_android_java_duplicate_create";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }

    std::unique_ptr<mpss::KeyPair> handle = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, handle) << mpss::get_error();

    const std::size_t public_key_size = handle->extract_key({});
    ASSERT_NE(0, public_key_size);
    std::vector<std::byte> original_public_key(public_key_size);
    ASSERT_EQ(public_key_size, handle->extract_key(original_public_key));

    handle->release_key();
    handle.reset();

    // The Java layer is called directly because the backend rejects a duplicate name before the JNI crossing.
    // A refused creation reports no generation, since there is no hold to report one for.
    const std::optional<std::int64_t> created = java_create_key(key_name, ecdsa_secp256r1_sha256);
    EXPECT_FALSE(created.has_value());
    EXPECT_NE(std::string::npos, mpss::get_error().find("Key with same name already exists"));

    std::unique_ptr<mpss::KeyPair> reopened = mpss::KeyPair::Open(key_name);
    ASSERT_NE(nullptr, reopened) << mpss::get_error();
    std::vector<std::byte> reopened_public_key(public_key_size);
    ASSERT_EQ(public_key_size, reopened->extract_key(reopened_public_key));
    EXPECT_EQ(original_public_key, reopened_public_key);

    ASSERT_TRUE(reopened->delete_key());
}

TEST(AndroidSecurityTest, StandaloneVerifyRejectsMismatchedAlgorithm)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256) || !mpss::is_algorithm_available(ecdsa_secp384r1_sha384))
    {
        GTEST_SKIP() << "Required algorithms are not supported by the Android backend.";
    }

    const std::string key_name = "test_android_algorithm_binding";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }

    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp384r1_sha384);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('a'));
    const std::vector<std::byte> signature = java_sign_hash(key_name, hash);
    ASSERT_FALSE(signature.empty());

    const std::size_t public_key_size = key->extract_key({});
    ASSERT_NE(0, public_key_size);
    std::vector<std::byte> public_key(public_key_size);
    ASSERT_EQ(public_key_size, key->extract_key(public_key));

    ASSERT_TRUE(java_verify_signature(hash, public_key, signature));
    ASSERT_FALSE(mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature));
}

TEST(AndroidJNITest, KeyPairCanMoveBetweenNativeThreads)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_native_thread_key";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::promise<std::unique_ptr<mpss::KeyPair>> key_promise;
    std::future<std::unique_ptr<mpss::KeyPair>> key_future = key_promise.get_future();
    std::string create_error;
    std::thread creator([&key_promise, &create_error, &key_name]() {
        std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
        if (nullptr == key)
        {
            create_error = mpss::get_error();
        }
        key_promise.set_value(std::move(key));
    });
    creator.join();

    std::unique_ptr<mpss::KeyPair> key = key_future.get();
    ASSERT_NE(nullptr, key) << create_error;

    const std::vector<std::byte> hash(32, static_cast<std::byte>('a'));
    bool succeeded = false;
    std::string use_error;
    std::thread user([key = std::move(key), &hash, &succeeded, &use_error]() mutable {
        std::vector<std::byte> signature(key->sign_hash(hash, {}));
        const std::size_t signature_size = key->sign_hash(hash, signature);
        if (0 == signature_size)
        {
            use_error = mpss::get_error();
            key.reset();
            return;
        }
        signature.resize(signature_size);

        std::vector<std::byte> public_key(key->extract_key({}));
        const std::size_t public_key_size = key->extract_key(public_key);
        if (0 == public_key_size)
        {
            use_error = mpss::get_error();
            key.reset();
            return;
        }
        public_key.resize(public_key_size);

        succeeded = key->verify(hash, signature) && mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature);
        if (!succeeded)
        {
            use_error = mpss::get_error();
        }
        key.reset();
    });
    user.join();

    ASSERT_TRUE(succeeded) << use_error;
}

TEST(AndroidJNITest, ConcurrentNativeThreadsUseIndependentJNIState)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_concurrent_jni";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('b'));
    std::vector<std::byte> signature(key->sign_hash(hash, {}));
    const std::size_t signature_size = key->sign_hash(hash, signature);
    ASSERT_NE(0, signature_size);
    signature.resize(signature_size);

    std::vector<std::byte> public_key(key->extract_key({}));
    const std::size_t public_key_size = key->extract_key(public_key);
    ASSERT_NE(0, public_key_size);
    public_key.resize(public_key_size);

    std::latch ready(2);
    std::latch start(1);
    std::array<bool, 2> succeeded{true, true};
    std::array<std::string, 2> errors;
    std::array<std::thread, 2> workers;
    for (std::size_t worker_index = 0; worker_index < workers.size(); ++worker_index)
    {
        workers[worker_index] = std::thread([&, worker_index]() {
            JavaVM *java_vm = nullptr;
            {
                mpss::impl::os::JNIEnvGuard overlap_guard;
                if (!overlap_guard.valid())
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = "Could not get JNI environment.";
                }
                else if (JNI_OK != overlap_guard->GetJavaVM(&java_vm))
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = "Could not get Java VM.";
                }

                ready.count_down();
                start.wait();
                if (succeeded[worker_index])
                {
                    for (std::size_t iteration = 0; iteration < 16; ++iteration)
                    {
                        if (!mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature))
                        {
                            succeeded[worker_index] = false;
                            errors[worker_index] = mpss::get_error();
                            break;
                        }
                    }
                }

                JNIEnv *nested_env = nullptr;
                if (succeeded[worker_index] &&
                    JNI_OK != java_vm->GetEnv(reinterpret_cast<void **>(&nested_env), JNI_VERSION_1_6))
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = "Nested guard detached its native thread.";
                }
            }

            if (nullptr == java_vm)
            {
                return;
            }

            JNIEnv *detached_env = nullptr;
            if (JNI_EDETACHED != java_vm->GetEnv(reinterpret_cast<void **>(&detached_env), JNI_VERSION_1_6))
            {
                succeeded[worker_index] = false;
                errors[worker_index] = "Native thread remained attached after its outer guard was destroyed.";
            }
        });
    }

    ready.wait();
    start.count_down();
    for (std::thread &worker : workers)
    {
        worker.join();
    }

    ASSERT_TRUE(succeeded[0]) << errors[0];
    ASSERT_TRUE(succeeded[1]) << errors[1];
}

TEST(AndroidJNITest, ConcurrentKeyCacheAccessIsSafe)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::array<std::string, 4> key_names{
        "test_android_concurrent_cache_0",
        "test_android_concurrent_cache_1",
        "test_android_concurrent_cache_2",
        "test_android_concurrent_cache_3",
    };
    for (const std::string &key_name : key_names)
    {
        if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
        {
            ASSERT_TRUE(existing->delete_key());
        }
    }
    SCOPE_GUARD({
        for (const std::string &key_name : key_names)
        {
            if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
            {
                cleanup->delete_key();
            }
        }
    });

    for (const std::string &key_name : key_names)
    {
        std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
        ASSERT_NE(nullptr, key) << mpss::get_error();
        key.reset();
    }

    std::latch ready(4);
    std::latch start(1);
    std::array<bool, 4> succeeded{true, true, true, true};
    std::array<std::string, 4> errors;
    std::array<std::thread, 4> workers;
    for (std::size_t worker_index = 0; worker_index < workers.size(); ++worker_index)
    {
        workers[worker_index] = std::thread([&, worker_index]() {
            ready.count_down();
            start.wait();

            for (std::size_t iteration = 0; iteration < 8; ++iteration)
            {
                std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open(key_names[worker_index]);
                if (nullptr == key)
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = mpss::get_error();
                    return;
                }

                std::vector<std::byte> public_key(key->extract_key({}));
                const std::size_t public_key_size = key->extract_key(public_key);
                if (0 == public_key_size)
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = mpss::get_error();
                    return;
                }
            }
        });
    }

    ready.wait();
    start.count_down();
    for (std::thread &worker : workers)
    {
        worker.join();
    }

    for (std::size_t worker_index = 0; worker_index < workers.size(); ++worker_index)
    {
        ASSERT_TRUE(succeeded[worker_index]) << key_names[worker_index] << ": " << errors[worker_index];
    }
}

TEST(AndroidJNITest, ConcurrentOpenAndDeleteLeaveCacheConsistent)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_concurrent_open_delete";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key) << mpss::get_error();
    key.reset();

    constexpr std::size_t opener_count = 8;
    std::latch ready(opener_count + 1);
    std::latch start(1);
    std::array<std::optional<std::int64_t>, opener_count> open_results;
    std::array<std::string, opener_count> open_errors;
    std::array<std::thread, opener_count> openers;
    for (std::size_t opener_index = 0; opener_index < openers.size(); ++opener_index)
    {
        openers[opener_index] = std::thread([&, opener_index]() {
            ready.count_down();
            start.wait();
            open_results[opener_index] = java_open_key(key_name);
            if (!open_results[opener_index].has_value())
            {
                open_errors[opener_index] = mpss::get_error();
            }
        });
    }

    std::optional<bool> delete_result;
    std::string delete_error;
    std::thread deleter([&]() {
        ready.count_down();
        start.wait();
        delete_result = java_key_operation("DeleteKey", key_name);
        if (!delete_result.has_value())
        {
            delete_error = mpss::get_error();
        }
    });

    ready.wait();
    start.count_down();
    for (std::thread &opener : openers)
    {
        opener.join();
    }
    deleter.join();

    ASSERT_TRUE(delete_result.has_value()) << delete_error;
    ASSERT_TRUE(*delete_result);
    for (std::size_t opener_index = 0; opener_index < open_results.size(); ++opener_index)
    {
        ASSERT_TRUE(open_results[opener_index].has_value()) << open_errors[opener_index];
    }

    const std::optional<std::int64_t> final_open_result = java_open_key(key_name);
    ASSERT_TRUE(final_open_result.has_value()) << mpss::get_error();
    ASSERT_GT(0, *final_open_result);

    std::unique_ptr<mpss::KeyPair> replacement = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, replacement) << mpss::get_error();
    ASSERT_TRUE(replacement->delete_key()) << mpss::get_error();
}

TEST(AndroidJNITest, PendingJavaExceptionIsCleared)
{
    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    JNIEnv *const env = guard.env();

    jclass missing_class = env->FindClass("com/microsoft/mpss/MissingForTest");
    ASSERT_TRUE(mpss::impl::os::utils::check_and_clear_exception(env, "finding a test-only missing class"));
    ASSERT_EQ(nullptr, missing_class);
    ASSERT_FALSE(env->ExceptionCheck());

    const std::string exception_error = mpss::get_error();
    EXPECT_NE(std::string::npos, exception_error.find("finding a test-only missing class"));
    EXPECT_NE(std::string::npos, exception_error.find("ClassNotFoundException"));

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    ASSERT_NE(nullptr, key_management);
    jmethodID take_error = env->GetStaticMethodID(key_management, "TakeError", "()Ljava/lang/String;");
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.TakeError"));
    ASSERT_NE(nullptr, take_error);
}

TEST(AndroidJNITest, JavaErrorIsContextualAndConsumed)
{
    const std::string key_name = "test_android_missing_error_detail";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }

    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    JNIEnv *const env = guard.env();

    ASSERT_EQ(nullptr, mpss::KeyPair::Open(key_name));
    mpss::impl::os::utils::report_java_error(env, "missing-key open probe");
    const std::string open_probe_error = mpss::get_error();
    EXPECT_NE(std::string::npos, open_probe_error.find("missing-key open probe failed without Java error detail."));
    EXPECT_EQ(std::string::npos, open_probe_error.find(key_name));

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    ASSERT_NE(nullptr, key_management);
    jmethodID get_security_level =
        env->GetStaticMethodID(key_management, "GetKeySecurityLevel", "(Ljava/lang/String;)I");
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.GetKeySecurityLevel"));
    ASSERT_NE(nullptr, get_security_level);

    jni_string java_key_name(env, env->NewStringUTF(key_name.c_str()));
    ASSERT_FALSE(
        mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"));
    ASSERT_FALSE(java_key_name.is_null());

    const jint security_level = env->CallStaticIntMethod(key_management, get_security_level, java_key_name.get());
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.GetKeySecurityLevel"));
    ASSERT_EQ(-1, security_level);

    mpss::impl::os::utils::report_java_error(env, "KeyManagement.GetKeySecurityLevel");
    const std::string first_error = mpss::get_error();
    EXPECT_NE(std::string::npos, first_error.find("KeyManagement.GetKeySecurityLevel failed:"));
    EXPECT_NE(std::string::npos, first_error.find("Could not get key: " + key_name));

    mpss::impl::os::utils::report_java_error(env, "second operation");
    const std::string second_error = mpss::get_error();
    EXPECT_NE(std::string::npos, second_error.find("second operation failed without Java error detail."));
    EXPECT_EQ(std::string::npos, second_error.find(key_name));
}

TEST(AndroidJNITest, BooleanUnboxingReusesCachedMetadata)
{
    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    JNIEnv *const env = guard.env();

    jclass boolean_class = mpss::impl::os::JNIHelper::boolean_class();
    ASSERT_NE(nullptr, boolean_class);
    jfieldID true_field = env->GetStaticFieldID(boolean_class, "TRUE", "Ljava/lang/Boolean;");
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "resolving Boolean.TRUE"));
    ASSERT_NE(nullptr, true_field);

    jni_object true_value(env, env->GetStaticObjectField(boolean_class, true_field));
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "getting Boolean.TRUE"));
    ASSERT_FALSE(true_value.is_null());

    for (std::size_t iteration = 0; iteration < 1024; ++iteration)
    {
        const std::optional<bool> value = mpss::impl::os::utils::unbox_boolean(env, true_value.get());
        ASSERT_TRUE(value.value_or(false));
    }
}

TEST(AndroidJNITest, StandaloneVerifyRecoversAfterMalformedPublicKey)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_java_exception";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('c'));
    std::vector<std::byte> signature(key->sign_hash(hash, {}));
    const std::size_t signature_size = key->sign_hash(hash, signature);
    ASSERT_NE(0, signature_size);
    signature.resize(signature_size);

    std::vector<std::byte> public_key(key->extract_key({}));
    const std::size_t public_key_size = key->extract_key(public_key);
    ASSERT_NE(0, public_key_size);
    public_key.resize(public_key_size);

    std::vector<std::byte> different_hash = hash;
    different_hash.front() ^= std::byte{1};
    ASSERT_FALSE(mpss::verify(different_hash, public_key, ecdsa_secp256r1_sha256, signature));

    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    mpss::impl::os::utils::report_java_error(guard.env(), "invalid-signature probe");
    EXPECT_NE(std::string::npos, mpss::get_error().find("invalid-signature probe failed without Java error detail."));

    std::vector<std::byte> malformed_public_key = public_key;
    malformed_public_key.front() = std::byte{0};
    ASSERT_FALSE(mpss::verify(hash, malformed_public_key, ecdsa_secp256r1_sha256, signature));
    const std::string verify_error = mpss::get_error();
    EXPECT_NE(std::string::npos, verify_error.find("KeyManagement.VerifySignature failed:"));
    EXPECT_NE(std::string::npos, verify_error.find("Invalid"));
    ASSERT_TRUE(mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature));
}

} // namespace mpss::tests
