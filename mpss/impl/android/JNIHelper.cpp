// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/android_utils.h"

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /*reserved*/)
try
{
    return mpss::impl::os::JNIHelper::init(vm) ? JNI_VERSION_1_6 : JNI_ERR;
}
catch (...)
{
    // An exception must not reach the JVM. Reporting failure here fails the library load.
    return JNI_ERR;
}

extern "C" JNIEXPORT void JNI_OnUnload(JavaVM *vm, void * /*reserved*/)
try
{
    mpss::impl::os::JNIHelper::uninit(vm);
}
catch (...) // NOLINT(bugprone-empty-catch) - the JVM is unloading; there is nothing to report to.
{
}

JavaVM *mpss::impl::os::JNIHelper::java_vm_ = nullptr;
jclass mpss::impl::os::JNIHelper::key_management_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::algorithm_class_ = nullptr;
jclass mpss::impl::os::JNIHelper::boolean_class_ = nullptr;
jmethodID mpss::impl::os::JNIHelper::boolean_value_method_ = nullptr;
jclass mpss::impl::os::JNIHelper::long_class_ = nullptr;
jmethodID mpss::impl::os::JNIHelper::long_value_method_ = nullptr;
thread_local bool mpss::impl::os::JNIEnvGuard::attached_ = false;
thread_local int mpss::impl::os::JNIEnvGuard::ref_count_ = 0;

namespace mpss::impl::os
{

bool JNIHelper::init(JavaVM *vm)
{
    if (nullptr == vm)
    {
        return false;
    }
    if (nullptr != java_vm_)
    {
        return vm == java_vm_ && initialized();
    }

    JNIEnv *env = nullptr;
    if (JNI_OK != vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) || nullptr == env)
    {
        return false;
    }

    java_vm_ = vm;

    const auto cache_class = [env](const char *name, jclass &destination) {
        jclass local_class = env->FindClass(name);
        if (utils::check_and_clear_exception(env, name) || nullptr == local_class)
        {
            return false;
        }

        destination = reinterpret_cast<jclass>(env->NewGlobalRef(local_class));
        const bool failed = utils::check_and_clear_exception(env, name) || nullptr == destination;
        env->DeleteLocalRef(local_class);
        return !failed;
    };

    if (!cache_class("com/microsoft/mpss/KeyManagement", key_management_class_) ||
        !cache_class("com/microsoft/mpss/Algorithm", algorithm_class_) ||
        !cache_class("java/lang/Boolean", boolean_class_) || !cache_class("java/lang/Long", long_class_))
    {
        uninit(vm);
        return false;
    }

    long_value_method_ = env->GetMethodID(long_class_, "longValue", "()J");
    if (utils::check_and_clear_exception(env, "resolving Long.longValue") || nullptr == long_value_method_)
    {
        uninit(vm);
        return false;
    }

    boolean_value_method_ = env->GetMethodID(boolean_class_, "booleanValue", "()Z");
    if (utils::check_and_clear_exception(env, "resolving Boolean.booleanValue") || nullptr == boolean_value_method_)
    {
        uninit(vm);
        return false;
    }

    return true;
}

void JNIHelper::uninit(JavaVM *vm)
{
    if (nullptr == vm || vm != java_vm_)
    {
        return;
    }

    JNIEnv *env = nullptr;
    if (JNI_OK == vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) && nullptr != env)
    {
        if (nullptr != boolean_class_)
        {
            env->DeleteGlobalRef(boolean_class_);
        }
        if (nullptr != long_class_)
        {
            env->DeleteGlobalRef(long_class_);
        }
        if (nullptr != algorithm_class_)
        {
            env->DeleteGlobalRef(algorithm_class_);
        }
        if (nullptr != key_management_class_)
        {
            env->DeleteGlobalRef(key_management_class_);
        }
    }

    boolean_value_method_ = nullptr;
    boolean_class_ = nullptr;
    long_value_method_ = nullptr;
    long_class_ = nullptr;
    algorithm_class_ = nullptr;
    key_management_class_ = nullptr;
    java_vm_ = nullptr;
}

bool JNIHelper::initialized()
{
    return nullptr != java_vm_ && nullptr != key_management_class_ && nullptr != algorithm_class_ &&
           nullptr != boolean_class_ && nullptr != boolean_value_method_ && nullptr != long_class_ &&
           nullptr != long_value_method_;
}

void JNIHelper::detach()
{
    if (nullptr != java_vm_)
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

    JNIEnv *env = nullptr;
    if (nullptr == java_vm_)
    {
        return nullptr;
    }

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
    return key_management_class_;
}

jclass JNIHelper::algorithm_class()
{
    return algorithm_class_;
}

jclass JNIHelper::boolean_class()
{
    return boolean_class_;
}

jmethodID JNIHelper::boolean_value_method()
{
    return boolean_value_method_;
}

jclass JNIHelper::long_class()
{
    return long_class_;
}

jmethodID JNIHelper::long_value_method()
{
    return long_value_method_;
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
    if (0 == ref_count_)
    {
        if (attached_)
        {
            JNIHelper::detach();
            attached_ = false;
        }
    }
}

} // namespace mpss::impl::os
