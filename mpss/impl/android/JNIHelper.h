// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <cstddef>
#include <jni.h>

namespace mpss::impl::os
{

class JNIHelper
{
  public:
    // Every Java method this backend calls, apart from the one used to describe a pending
    // exception, which stays self-contained so that a failure here can still be reported.
    //
    // A descriptor is a string the runtime resolves, so one that has drifted from the Java it names
    // compiles cleanly and fails only on a device. Keeping them together makes them checkable
    // against the built JAR in one place, and resolving them here means a mismatch refuses the
    // backend at registration rather than surfacing when a caller signs something.
    //
    // Java names alone do not identify a method, since DeleteKey and VerifySignature each have two
    // overloads, so these are named for what they do.
    enum class JavaMethod : std::size_t
    {
        open_key,
        create_key,
        close_key,
        sign_hash,
        verify_signature,
        verify_standalone_signature,
        get_public_key,
        delete_key_by_generation,
        delete_key_by_name,
        get_key_algorithm,
        get_key_security_level,
        take_error,
        algorithm_name,
        boolean_value,
        long_value,
        count
    };

    static bool init(JavaVM *vm);
    static void uninit(JavaVM *vm);
    [[nodiscard]]
    static bool initialized();
    static void detach();
    static JNIEnv *get_env(bool *did_attach = nullptr);
    static jclass key_management_class();
    static jclass algorithm_class();
    static jclass boolean_class();
    static jclass long_class();

    // Resolved at init. Null only when the backend is not initialized.
    static jmethodID method(JavaMethod id);

  private:
    static JavaVM *java_vm_;
    static jclass key_management_class_;
    static jclass algorithm_class_;
    static jclass boolean_class_;
    static jclass long_class_;
    static std::array<jmethodID, static_cast<std::size_t>(JavaMethod::count)> methods_;
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
