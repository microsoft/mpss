// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "../mpss_impl.h"
#include "../../utils/scope_guard.h"
#include "../../utils/utilities.h"

#include <sstream>

#include <windows.h>
#include <ncrypt.h>

namespace {
    NCRYPT_PROV_HANDLE GetProvider()
    {
        NCRYPT_PROV_HANDLE hProvider = 0;

        SECURITY_STATUS status = ::NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, /* dwFlags */ 0);
        if (ERROR_SUCCESS != status) {
            std::stringstream ss;
            ss << "NCryptOpenStorageProvider failed with error code " << mpss::utils::to_hex(status);
            mpss::utils::set_error(ss.str());
            return 0;
        }

        return hProvider;
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

            SECURITY_STATUS status = ::NCryptCreatePersistedKey(hProvider, &hKey, BCRYPT_ECDSA_P256_ALGORITHM, wname.c_str(), 0, NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptCreatePersistedKey failed with error code " << mpss::utils::to_hex(status);
                mpss::utils::set_error(ss.str());
                return -1;
            }

            status = ::NCryptFinalizeKey(hKey, /* dwFlags */ 0);
            if (ERROR_SUCCESS != status) {
                std::stringstream ss;
                ss << "NCryptFinalizeKey failed with error code " << mpss::utils::to_hex(status);
                mpss::utils::set_error(ss.str());
                return -1;
            }

            return 0;
        }
    }
}
