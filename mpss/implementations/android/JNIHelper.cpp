// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/android/JNIHelper.h"
#include <mutex>

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    // JNI initialization
    mpss::impl::JNIHelper::Init(vm);
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    // Uninitialize
}

JavaVM *mpss::impl::JNIHelper::java_vm_ = nullptr;
bool mpss::impl::JNIEnvGuard::attached_ = false;
int mpss::impl::JNIEnvGuard::ref_count_ = 0;

namespace mpss::impl {
    void JNIHelper::Init(JavaVM *vm)
    {
        java_vm_ = vm;
    }

    void JNIHelper::Detach()
    {
        if (java_vm_) {
            java_vm_->DetachCurrentThread();
        }
    }

    JNIEnv *JNIHelper::GetEnv(bool *did_attach)
    {
        JNIEnv *env = nullptr;
        if (java_vm_ == nullptr)
            return nullptr;

        jint result = java_vm_->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
        if (result == JNI_OK) {
            if (did_attach)
                *did_attach = false;
            return env;
        } else if (result == JNI_EDETACHED) {
            if (java_vm_->AttachCurrentThread(&env, nullptr) == 0) {
                if (did_attach)
                    *did_attach = true;
                return env;
            } else {
                return nullptr;
            }
        } else {
            return nullptr;
        }
    }

    // RAII Wrapper
    JNIEnvGuard::JNIEnvGuard()
    {
        ref_count_++;
        bool attached = false;
        env_ = JNIHelper::GetEnv(&attached);
        if (attached) {
            attached_ = true;
        }
    }

    JNIEnvGuard::~JNIEnvGuard()
    {
        ref_count_--;
        if (ref_count_ == 0) {
            if (attached_) {
                JNIHelper::Detach();
                attached_ = false;
            }
        }
    }
} // namespace mpss::impl
