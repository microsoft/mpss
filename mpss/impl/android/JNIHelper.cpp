// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/mpss.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <format>
#include <mutex>
#include <ranges>
#include <string>

std::mutex mpss::impl::os::JNIHelper::init_mutex_;
std::atomic<bool> mpss::impl::os::JNIHelper::initialized_{false};
JavaVM *mpss::impl::os::JNIHelper::java_vm_ = nullptr;
jclass mpss::impl::os::JNIHelper::key_management_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::algorithm_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::boolean_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::long_class_ = nullptr;
std::array<jmethodID, static_cast<std::size_t>(mpss::impl::os::JNIHelper::JavaMethod::count)>
    mpss::impl::os::JNIHelper::methods_{};
thread_local bool mpss::impl::os::JNIEnvGuard::attached_ = false;
thread_local int mpss::impl::os::JNIEnvGuard::ref_count_ = 0;

namespace mpss::impl::os
{

namespace
{
enum class OwnerClass
{
    key_management,
    algorithm,
    boolean_box,
    long_box
};

struct MethodSpec
{
    JNIHelper::JavaMethod id;
    OwnerClass owner;
    const char *name;
    const char *descriptor;
    bool is_static;
};

// The descriptors this backend depends on. Checked against what the built JAR exposes rather than
// against the Java sources, since a method resolved by a string cannot fail to compile.
constexpr std::array<MethodSpec, static_cast<std::size_t>(JNIHelper::JavaMethod::count)> method_table{{
    {.id = JNIHelper::JavaMethod::open_key,
     .owner = OwnerClass::key_management,
     .name = "OpenKey",
     .descriptor = "(Ljava/lang/String;)Ljava/lang/Long;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::create_key,
     .owner = OwnerClass::key_management,
     .name = "CreateKey",
     .descriptor = "(Ljava/lang/String;Lcom/microsoft/mpss/Algorithm;)Ljava/lang/Long;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::close_key,
     .owner = OwnerClass::key_management,
     .name = "CloseKey",
     .descriptor = "(Ljava/lang/String;J)V",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::sign_hash,
     .owner = OwnerClass::key_management,
     .name = "SignHash",
     .descriptor = "(Ljava/lang/String;[BJ)[B",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::verify_signature,
     .owner = OwnerClass::key_management,
     .name = "VerifySignature",
     .descriptor = "(Ljava/lang/String;[B[BJ)Ljava/lang/Boolean;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::verify_standalone_signature,
     .owner = OwnerClass::key_management,
     .name = "VerifySignature",
     .descriptor = "([B[B[B)Ljava/lang/Boolean;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::get_public_key,
     .owner = OwnerClass::key_management,
     .name = "GetPublicKey",
     .descriptor = "(Ljava/lang/String;J)[B",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::delete_key_by_generation,
     .owner = OwnerClass::key_management,
     .name = "DeleteKey",
     .descriptor = "(Ljava/lang/String;J)Ljava/lang/Boolean;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::delete_key_by_name,
     .owner = OwnerClass::key_management,
     .name = "DeleteKey",
     .descriptor = "(Ljava/lang/String;)Ljava/lang/Boolean;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::get_key_algorithm,
     .owner = OwnerClass::key_management,
     .name = "GetKeyAlgorithm",
     .descriptor = "(Ljava/lang/String;)Lcom/microsoft/mpss/Algorithm;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::get_key_security_level,
     .owner = OwnerClass::key_management,
     .name = "GetKeySecurityLevel",
     .descriptor = "(Ljava/lang/String;J)I",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::take_error,
     .owner = OwnerClass::key_management,
     .name = "TakeError",
     .descriptor = "()Ljava/lang/String;",
     .is_static = true},
    {.id = JNIHelper::JavaMethod::algorithm_name,
     .owner = OwnerClass::algorithm,
     .name = "name",
     .descriptor = "()Ljava/lang/String;",
     .is_static = false},
    {.id = JNIHelper::JavaMethod::boolean_value,
     .owner = OwnerClass::boolean_box,
     .name = "booleanValue",
     .descriptor = "()Z",
     .is_static = false},
    {.id = JNIHelper::JavaMethod::long_value,
     .owner = OwnerClass::long_box,
     .name = "longValue",
     .descriptor = "()J",
     .is_static = false},
}};
} // namespace

bool JNIHelper::init(JavaVM *vm)
{
    if (nullptr == vm)
    {
        mpss::utils::log_and_set_error("The Java VM cannot be null.");
        return false;
    }

    const std::scoped_lock lock(init_mutex_);
    if (initialized_.load(std::memory_order_acquire))
    {
        if (vm != java_vm_)
        {
            mpss::utils::log_and_set_error("MPSS is already initialized for a different Java VM.");
            return false;
        }
        return true;
    }

    JNIEnv *env = nullptr;
    if (JNI_OK != vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) || nullptr == env)
    {
        mpss::utils::log_and_set_error("The calling thread is not attached to the Java VM.");
        return false;
    }

    bool succeeded = false;
    SCOPE_GUARD({
        if (!succeeded)
        {
            reset(env);
        }
    });

    const auto cache_class = [env](const char *name, jclass &destination) {
        jclass local_class = env->FindClass(name);
        if (utils::check_and_clear_exception(env, std::format("finding Java class '{}'", name)))
        {
            return false;
        }
        if (nullptr == local_class)
        {
            mpss::utils::log_and_set_error("Could not find Java class '{}'.", name);
            return false;
        }

        destination = reinterpret_cast<jclass>(env->NewGlobalRef(local_class));
        const bool threw = utils::check_and_clear_exception(env, std::format("referencing Java class '{}'", name));
        env->DeleteLocalRef(local_class);
        if (threw)
        {
            return false;
        }
        if (nullptr == destination)
        {
            mpss::utils::log_and_set_error("Could not reference Java class '{}'.", name);
            return false;
        }
        return true;
    };

    if (!cache_class("com/microsoft/mpss/KeyManagement", key_management_class_) ||
        !cache_class("com/microsoft/mpss/Algorithm", algorithm_class_) ||
        !cache_class("java/lang/Boolean", boolean_class_) || !cache_class("java/lang/Long", long_class_))
    {
        return false;
    }

    const auto owner_class = [](OwnerClass owner) -> jclass {
        switch (owner)
        {
        case OwnerClass::key_management:
            return key_management_class_;
        case OwnerClass::algorithm:
            return algorithm_class_;
        case OwnerClass::boolean_box:
            return boolean_class_;
        case OwnerClass::long_box:
            return long_class_;
        }
        return nullptr;
    };

    const auto cache_method = [env, &owner_class](const MethodSpec &spec) {
        jclass owner = owner_class(spec.owner);
        if (nullptr == owner)
        {
            return false;
        }

        jmethodID resolved = spec.is_static ? env->GetStaticMethodID(owner, spec.name, spec.descriptor)
                                            : env->GetMethodID(owner, spec.name, spec.descriptor);
        if (utils::check_and_clear_exception(env,
                                             std::format("resolving Java method '{}{}'", spec.name, spec.descriptor)))
        {
            return false;
        }
        if (nullptr == resolved)
        {
            mpss::utils::log_and_set_error("Could not resolve Java method '{}{}'.", spec.name, spec.descriptor);
            return false;
        }

        methods_.at(static_cast<std::size_t>(spec.id)) = resolved;
        return true;
    };

    if (!std::ranges::all_of(method_table, cache_method))
    {
        return false;
    }

    java_vm_ = vm;
    succeeded = true;
    initialized_.store(true, std::memory_order_release);
    return true;
}

void JNIHelper::reset(JNIEnv *env)
{
    for (jclass *cached : {&key_management_class_, &algorithm_class_, &boolean_class_, &long_class_})
    {
        if (nullptr != *cached)
        {
            env->DeleteGlobalRef(*cached);
            *cached = nullptr;
        }
    }
    methods_.fill(nullptr);
}

bool JNIHelper::initialized()
{
    return initialized_.load(std::memory_order_acquire);
}

void JNIHelper::detach()
{
    if (initialized())
    {
        java_vm_->DetachCurrentThread();
    }
}

JNIEnv *JNIHelper::get_env(bool *did_attach)
{
    if (nullptr != did_attach)
    {
        *did_attach = false;
    }

    if (!initialized())
    {
        return nullptr;
    }

    JNIEnv *env = nullptr;
    const jint result = java_vm_->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (JNI_OK == result)
    {
        return env;
    }
    if (JNI_EDETACHED == result)
    {
        if (0 == java_vm_->AttachCurrentThread(&env, nullptr))
        {
            if (nullptr != did_attach)
            {
                *did_attach = true;
            }
            return env;
        }
        return nullptr;
    }
    return nullptr;
}

jclass JNIHelper::key_management_class()
{
    return initialized() ? key_management_class_ : nullptr;
}

jclass JNIHelper::algorithm_class()
{
    return initialized() ? algorithm_class_ : nullptr;
}

jclass JNIHelper::boolean_class()
{
    return initialized() ? boolean_class_ : nullptr;
}

jclass JNIHelper::long_class()
{
    return initialized() ? long_class_ : nullptr;
}

jmethodID JNIHelper::method(JavaMethod id)
{
    return initialized() ? methods_.at(static_cast<std::size_t>(id)) : nullptr;
}

// RAII Wrapper.
JNIEnvGuard::JNIEnvGuard()
{
    bool attached = false;
    env_ = JNIHelper::get_env(&attached);
    if (nullptr == env_)
    {
        return;
    }

    ref_count_++;
    if (attached)
    {
        attached_ = true;
    }
}

JNIEnvGuard::~JNIEnvGuard()
{
    if (nullptr == env_)
    {
        return;
    }

    ref_count_--;
    if (0 == ref_count_ && attached_)
    {
        JNIHelper::detach();
        attached_ = false;
    }
}

} // namespace mpss::impl::os

namespace mpss
{

bool initialize_android(JavaVM *vm) noexcept
try
{
    clear_error();
    return impl::os::JNIHelper::init(vm);
}
catch (...)
{
    utils::set_internal_error();
    return false;
}

} // namespace mpss
