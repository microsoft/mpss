// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <jni.h>

namespace mpss::impl::os
{

class JNIHelper
{
  public:
    static bool init(JavaVM *vm);
    static void uninit(JavaVM *vm);
    [[nodiscard]]
    static bool initialized();
    static void detach();
    static JNIEnv *get_env(bool *did_attach = nullptr);
    static jclass key_management_class();
    static jclass algorithm_class();
    static jclass boolean_class();
    static jmethodID boolean_value_method();
    static jclass long_class();
    static jmethodID long_value_method();

  private:
    static JavaVM *java_vm_;
    static jclass key_management_class_;
    static jclass algorithm_class_;
    static jclass boolean_class_;
    static jmethodID boolean_value_method_;
    static jclass long_class_;
    static jmethodID long_value_method_;
};

// RAII Wrapper
class JNIEnvGuard
{
  public:
    JNIEnvGuard();
    virtual ~JNIEnvGuard();

    JNIEnvGuard(const JNIEnvGuard &) = delete;
    JNIEnvGuard &operator=(const JNIEnvGuard &) = delete;
    JNIEnvGuard(JNIEnvGuard &&) = delete;
    JNIEnvGuard &operator=(JNIEnvGuard &&) = delete;

    JNIEnv *operator->()
    {
        return env_;
    }

    [[nodiscard]]
    bool valid() const
    {
        return nullptr != env_;
    }

    [[nodiscard]]
    JNIEnv *env() const
    {
        return env_;
    }

  private:
    JNIEnv *env_ = nullptr;

    static thread_local bool attached_;
    static thread_local int ref_count_;
};

} // namespace mpss::impl::os
