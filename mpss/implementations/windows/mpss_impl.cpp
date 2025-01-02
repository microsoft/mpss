// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../mpss_impl.h"
#include "../../utils/scope_guard.h"
#include "../../utils/utilities.h"

#include <sstream>

#include <windows.h>
#include <ncrypt.h>

namespace {
    // Error code of the last error that occurred
    thread_local SECURITY_STATUS _last_error = ERROR_SUCCESS;

    void set_error(SECURITY_STATUS status, const std::string& error)
    {
        _last_error = status;
        mpss::utils::set_error(error);
    }

    NCRYPT_PROV_HANDLE GetProvider()
    {
        NCRYPT_PROV_HANDLE hProvider = 0;

        SECURITY_STATUS status = ::NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenStorageProvider failed with error code " << mpss::utils::to_hex(status);
            set_error(status, ss.str());
            return 0;
        }

        return hProvider;
    }

    NCRYPT_KEY_HANDLE GetKey(const std::string& name)
    {
        NCRYPT_PROV_HANDLE hProvider = GetProvider();
        if (!hProvider) {
            return 0;
        }

        SCOPE_GUARD(::NCryptFreeObject(hProvider));

        NCRYPT_KEY_HANDLE hKey = 0;
        std::wstring wname(name.begin(), name.end());
        SECURITY_STATUS status = ::NCryptOpenKey(hProvider, &hKey, wname.c_str(), /* dwLegacyKeySpec */ 0, /* dwFlags */ NCRYPT_MACHINE_KEY_FLAG);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenKey failed with error code " << mpss::utils::to_hex(status);
            set_error(status, ss.str());
            return 0;
        }

        return hKey;
    }
}

namespace mpss
{
    namespace implementation
    {
        int create_key(const std::string& name)
        {
            NCRYPT_PROV_HANDLE hProvider = GetProvider();
            if (!hProvider) {
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(hProvider));

            NCRYPT_KEY_HANDLE hKey = 0;
            std::wstring wname(name.begin(), name.end());

            SECURITY_STATUS status = ::NCryptCreatePersistedKey(
                hProvider,
                &hKey,
                BCRYPT_ECDSA_P256_ALGORITHM,
                wname.c_str(),
                /* dwLegacyKeySpec */ 0,
                NCRYPT_MACHINE_KEY_FLAG);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptCreatePersistedKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            DWORD dwExportPolicy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            status = ::NCryptSetProperty(
                hKey,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                reinterpret_cast<PBYTE>(&dwExportPolicy),
                sizeof(dwExportPolicy),
                NCRYPT_PERSIST_FLAG);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSetProperty failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            status = ::NCryptFinalizeKey(hKey, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptFinalizeKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            return 0;
        }

        int delete_key(const std::string& name)
        {
            NCRYPT_KEY_HANDLE hKey = GetKey(name);
            if (!hKey) {
                // If the key does not exist, consider it deleted
                if (NTE_BAD_KEYSET == _last_error) {
                    return 0;
                }
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(hKey));

            SECURITY_STATUS status = ::NCryptDeleteKey(hKey, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptDeleteKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            return 0;
        }

        std::string sign(const std::string& name, const std::string& data)
        {
            std::string signature;
            NCRYPT_KEY_HANDLE hKey = GetKey(name);
            if (!hKey) {
                return signature;
            }

            SCOPE_GUARD(::NCryptFreeObject(hKey));

            DWORD dwSignatureSize = 0;

            // Get signature size
            SECURITY_STATUS status = ::NCryptSignHash(
                hKey,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<BYTE*>(const_cast<char*>(data.data())),
                static_cast<DWORD>(data.size()),
                nullptr,
                0,
                &dwSignatureSize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return signature;
            }

            // Get actual signature
            signature.resize(dwSignatureSize);
            status = ::NCryptSignHash(
                hKey,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<BYTE*>(const_cast<char*>(data.data())),
                static_cast<DWORD>(data.size()),
                reinterpret_cast<PBYTE>(&signature[0]),
                static_cast<DWORD>(signature.size()),
                &dwSignatureSize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptSignHash failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return std::string();
            }

            return signature;
        }

        int verify(const std::string& name, const std::string& data, const std::string& signature)
        {
            NCRYPT_KEY_HANDLE hKey = GetKey(name);
            if (!hKey) {
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(hKey));

            std::string data_copy = data;
            SECURITY_STATUS status = ::NCryptVerifySignature(
                hKey,
                /* pPaddingInfo */ nullptr,
                reinterpret_cast<BYTE*>(data_copy.data()),
                static_cast<DWORD>(data_copy.size()),
                reinterpret_cast<BYTE*>(const_cast<char*>(signature.data())),
                static_cast<DWORD>(signature.size()),
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptVerifySignature failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            return 0;
        }

        int get_key(const std::string& name, std::string& vk_out, std::string& sk_out)
        {
            NCRYPT_KEY_HANDLE hKey = GetKey(name);
            if (!hKey) {
                return -1;
            }
            SCOPE_GUARD(::NCryptFreeObject(hKey));

            // Get the public key size
            DWORD dwPublicKeySize = 0;
            SECURITY_STATUS status = ::NCryptExportKey(
                hKey,
                /* hExportKey */ 0,
                BCRYPT_ECCPUBLIC_BLOB,
                /* pParameterList */ nullptr,
                /* pbOutput */ nullptr,
                /* cbOutput */ 0,
                &dwPublicKeySize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            // Actually get the public key
            BYTE* pbPublicKey = new BYTE[dwPublicKeySize];
            SCOPE_GUARD(delete[] pbPublicKey);

            status = ::NCryptExportKey(
                hKey,
                /* hExportKey */ 0,
                BCRYPT_ECCPUBLIC_BLOB,
                /* pParameterList */ nullptr,
                pbPublicKey,
                dwPublicKeySize,
                &dwPublicKeySize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            BCRYPT_ECCKEY_BLOB* pEccKeyBlob = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pbPublicKey);
            if (pEccKeyBlob->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC) {
                set_error(status, "Invalid public key magic, should be BCRYPT_ECDSA_PUBLIC_P256_MAGIC");
                return -1;
            }

            BYTE* pDataStart = reinterpret_cast<BYTE*>(pEccKeyBlob) + sizeof(BCRYPT_ECCKEY_BLOB);
            vk_out.assign(reinterpret_cast<char*>(pDataStart), dwPublicKeySize - sizeof(BCRYPT_ECCKEY_BLOB));

            // Get the private key size
            DWORD dwPrivateKeySize = 0;
            status = ::NCryptExportKey(
                hKey,
                /* hExportKey */ 0,
                BCRYPT_ECCPRIVATE_BLOB,
                /* pParameterList */ nullptr,
                /* pbOutput */ nullptr,
                /* cbOutput */ 0,
                &dwPrivateKeySize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            // Actually get the private key
            BYTE* pbPrivateKey = new BYTE[dwPrivateKeySize];
            SCOPE_GUARD(delete[] pbPrivateKey);

            status = ::NCryptExportKey(
                hKey,
                /* hExportKey */ 0,
                BCRYPT_ECCPRIVATE_BLOB,
                /* pParameterList */ nullptr,
                pbPrivateKey,
                dwPrivateKeySize,
                &dwPrivateKeySize,
                /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptExportKey failed with error code " << mpss::utils::to_hex(status);
                set_error(status, ss.str());
                return -1;
            }

            BCRYPT_ECCKEY_BLOB* pPrivateKeyBlob = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pbPrivateKey);
            if (pPrivateKeyBlob->dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC) {
                set_error(status, "Invalid private key magic, should be BCRYPT_ECDSA_PRIVATE_P256_MAGIC");
                return -1;
            }

            pDataStart = reinterpret_cast<BYTE*>(pPrivateKeyBlob) + sizeof(BCRYPT_ECCKEY_BLOB);
            sk_out.assign(reinterpret_cast<char*>(pDataStart), dwPrivateKeySize - sizeof(BCRYPT_ECCKEY_BLOB));

            return 0;
        }

        const std::string& get_error()
        {
            return mpss::utils::get_error();
        }
    }
}
