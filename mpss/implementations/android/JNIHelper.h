// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <jni.h>

namespace mpss::impl {
    class JNIHelper {
    public:
        static void Init(JavaVM *vm);
        static void Detach();
        static JNIEnv *GetEnv(bool *did_attach = nullptr);

    private:
        static JavaVM *java_vm_;
    };

    // RAII Wrapper
    class JNIEnvGuard {
    public:
        JNIEnvGuard();
        virtual ~JNIEnvGuard();

        JNIEnv *operator->() { return env_; }
        [[nodiscard]] JNIEnv *Env() const { return env_; }

    private:
        JNIEnv *env_ = nullptr;

    private:
        static bool attached_;
        static int ref_count_;
    };
}
