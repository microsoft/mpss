// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/utilities.h"
#include "android_keypair.h"
#include "android_utils.h"
#include "JNIHelper.h"
#include "JNIObject.h"

namespace mpss::impl {
    using jni_class = utils::JNIObj<jclass>;
    using jni_string = utils::JNIObj<jstring>;
    using jni_object = utils::JNIObj<jobject>;
    using jni_bytearray = utils::JNIObj<jbyteArray>;

    std::unique_ptr<KeyPair> create_key(std::string_view name, Algorithm algorithm) {
        JNIEnvGuard guard;
        jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement java class");
            return {};
        }

        jmethodID mid = guard->GetStaticMethodID(km.get(), "CreateKey", "(Ljava/lang/String;Lcom/microsoft/research/mpss/Algorithm;)Ljava/lang/Boolean;");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.CreateKey java method");
            return {};
        }

        std::string keyNameStr(name);
        jni_string keyName(guard.Env(), guard->NewStringUTF(keyNameStr.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not convert key name to java String");
            return {};
        }

        jni_class algorithmClass(guard.Env(), guard->FindClass("com/microsoft/research/mpss/Algorithm"));
        if (algorithmClass.is_null()) {
            mpss::utils::set_error("Could not get Algorithm java class");
            return {};
        }

        jfieldID algoFieldId = nullptr;

        switch(algorithm) {
            case Algorithm::ecdsa_secp256r1_sha256:
                algoFieldId = guard->GetStaticFieldID(algorithmClass.get(), "secp256r1", "Lcom/microsoft/research/mpss/Algorithm;");
                break;
            case Algorithm::ecdsa_secp384r1_sha384:
                algoFieldId = guard->GetStaticFieldID(algorithmClass.get(), "secp384r1", "Lcom/microsoft/research/mpss/Algorithm;");
                break;
            case Algorithm::ecdsa_secp521r1_sha512:
                algoFieldId = guard->GetStaticFieldID(algorithmClass.get(), "secp521r1", "Lcom/microsoft/research/mpss/Algorithm;");
                break;
            default:
                mpss::utils::set_error("Unsupported algorithm");
                return {};
        }

        if (nullptr == algoFieldId) {
            mpss::utils::set_error("Could not find appropriate enum value for Algorithm");
            return {};
        }

        jni_object algorithmValue(guard.Env(), guard->GetStaticObjectField(algorithmClass.get(), algoFieldId));
        if (algorithmValue.is_null()) {
            mpss::utils::set_error("Could not get object for Algorithm value");
            return {};
        }

        jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid, keyName.get(), algorithmValue.get()));
        if (result.is_null()) {
            mpss::utils::set_error("KeyManagement.CreateKey returned null");
            return {};
        }

        if (!utils::UnboxBoolean(guard.Env(), result.get())) {
            // Error happened in Java side
            mpss::utils::set_error(mpss::impl::utils::GetError(guard.Env()));
            return {};
        }

        return std::make_unique<AndroidKeyPair>(algorithm, name);
    }

    std::unique_ptr<KeyPair> open_key(std::string_view name) {
        JNIEnvGuard guard;
        jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement java class");
            return {};
        }

        std::string nameStr(name);
        jni_string keyName(guard.Env(), guard->NewStringUTF(nameStr.c_str()));
        if (keyName.is_null()) {
            mpss::utils::set_error("Could not create key name java string");
            return {};
        }

        jmethodID mid = guard->GetStaticMethodID(km.get(), "OpenKey", "(Ljava/lang/String;)Ljava/lang/Boolean;");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.OpenKey java method");
            return {};
        }

        jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid, keyName.get()));
        if (result.is_null()) {
            mpss::utils::set_error("KeyManagement.OpenKey returned null");
            return {};
        }

        if (!utils::UnboxBoolean(guard.Env(), result.get())) {
            // Java method failed
            mpss::utils::set_error(mpss::impl::utils::GetError(guard.Env()));
            return {};
        }

        // Now we need the Algorithm
        jmethodID mid_algo = guard->GetStaticMethodID(km.get(), "GetKeyAlgorithm", "(Ljava/lang/String;)Lcom/microsoft/research/mpss/Algorithm;");
        if (nullptr == mid_algo) {
            mpss::utils::set_error("Failed to get KeyManagement.GetKeyAlgorithm method");
            return {};
        }

        jni_object algo_result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid_algo, keyName.get()));
        if (algo_result.is_null()) {
            mpss::utils::set_error("KeyManagement.GetKeyAlgorithm returned null");
            return {};
        }

        jni_class algo_class(guard.Env(), guard->GetObjectClass(algo_result.get()));
        if (algo_class.is_null()) {
            mpss::utils::set_error("Failed to get Java class for Algorithm");
            return {};
        }

        jmethodID nameMethod = guard->GetMethodID(algo_class.get(), "name", "()Ljava/lang/String;");
        if (nullptr == nameMethod) {
            mpss::utils::set_error("Could not get method id for Algorithm.name");
            return {};
        }

        jni_string algo_name(
                guard.Env(),
                reinterpret_cast<jstring>(guard->CallObjectMethod(algo_result.get(), nameMethod)));
        if (algo_name.is_null()) {
            mpss::utils::set_error("Could not get name of enum Algorithm");
            return {};
        }

        std::string algo_name_str = mpss::impl::utils::GetString(guard.Env(), algo_name.get());
        Algorithm algorithm = Algorithm::unsupported;

        if (algo_name_str == "secp256r1")  {
            algorithm = Algorithm::ecdsa_secp256r1_sha256;
        } else if (algo_name_str == "secp384r1") {
            algorithm = Algorithm::ecdsa_secp384r1_sha384;
        } else if (algo_name_str == "secp521r1") {
            algorithm = Algorithm::ecdsa_secp521r1_sha512;
        }

        // Finally, we can return the key
        return std::make_unique<AndroidKeyPair>(algorithm, name);
    }

    bool verify(gsl::span<const std::byte> hash, gsl::span<const std::byte> public_key, Algorithm algorithm, gsl::span<const std::byte> sig) {
        JNIEnvGuard guard;

        if (!mpss::utils::check_hash_length(hash, algorithm)) {
            mpss::utils::set_error("Invalid hash length for the specified algorithm");
            return false;
        }

        jni_class km(guard.Env(), utils::GetKeyManagementClass(guard.Env()));
        if (km.is_null()) {
            mpss::utils::set_error("Could not get KeyManagement java class");
            return false;
        }

        jmethodID  mid = guard->GetStaticMethodID(km.get(), "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
        if (nullptr == mid) {
            mpss::utils::set_error("Could not get KeyManagement.VerifySignature java method");
            return false;
        }

        jni_bytearray hash_arr(guard.Env(), utils::ToJByteArray(guard.Env(), hash));
        if (hash_arr.is_null()) {
            mpss::utils::set_error("Could not convert hash to jbyte array");
            return false;
        }

        jni_bytearray pk_arr(guard.Env(), utils::ToJByteArray(guard.Env(), public_key));
        if (pk_arr.is_null()) {
            mpss::utils::set_error("Could not convert public key to jbyte array");
            return false;
        }

        jni_bytearray sig_arr(guard.Env(), utils::ToJByteArray(guard.Env(), sig));
        if (sig_arr.is_null()) {
            mpss::utils::set_error("Could not convert signature to jbyte array");
            return false;
        }

        jni_object result(guard.Env(), guard->CallStaticObjectMethod(km.get(), mid, hash_arr.get(), sig_arr.get(), pk_arr.get()));
        if (result.is_null()) {
            mpss::utils::set_error("KeyManagement.VerifySignature returned null");
            return false;
        }

        bool verified = utils::UnboxBoolean(guard.Env(), result.get());
        if (!verified) {
            // Update error information
            mpss::utils::set_error(mpss::impl::utils::GetError(guard.Env()));
        }

        return verified;
    }
}
