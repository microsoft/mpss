// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    // JNI initialization.
    mpss::impl::os::JNIHelper::Init(vm);
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    // Uninitialize.
}

JavaVM *mpss::impl::os::JNIHelper::java_vm_ = nullptr;
bool mpss::impl::os::JNIEnvGuard::attached_ = false;
int mpss::impl::os::JNIEnvGuard::ref_count_ = 0;

namespace mpss::impl::os
{

void JNIHelper::Init(JavaVM *vm)
{
    java_vm_ = vm;
}

void JNIHelper::Detach()
{
    if (nullptr != java_vm_)
    {
        java_vm_->DetachCurrentThread();
    }
}

JNIEnv *JNIHelper::GetEnv(bool *did_attach)
{
    JNIEnv *env = nullptr;
    if (nullptr == java_vm_)
    {
        return nullptr;
    }

    const jint result = java_vm_->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (JNI_OK == result)
    {
        if (nullptr != did_attach)
        {
            *did_attach = false;
        }
        return env;
    }
    else if (JNI_EDETACHED == result)
    {
        if (0 == java_vm_->AttachCurrentThread(&env, nullptr))
        {
            if (nullptr != did_attach)
            {
                *did_attach = true;
            }
            return env;
        }
        else
        {
            return nullptr;
        }
    }
    else
    {
        return nullptr;
    }
}

// RAII Wrapper.
JNIEnvGuard::JNIEnvGuard()
{
    ref_count_++;
    bool attached = false;
    env_ = JNIHelper::GetEnv(&attached);
    if (attached)
    {
        attached_ = true;
    }
}

JNIEnvGuard::~JNIEnvGuard()
{
    ref_count_--;
    if (0 == ref_count_)
    {
        if (attached_)
        {
            JNIHelper::Detach();
            attached_ = false;
        }
    }
}

} // namespace mpss::impl::os
