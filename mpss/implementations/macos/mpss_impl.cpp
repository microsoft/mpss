// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/implementations/mpss_impl.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"

namespace mpss
{
    namespace impl
    {
        std::unique_ptr<KeyPairHandle> create_key(std::string_view name, SignatureAlgorithm algorithm)
        {
            return {};
        }

        std::unique_ptr<KeyPairHandle> open_key(std::string_view name)
        {
            return {};
        }

        int delete_key(const KeyPairHandlePtr handle)
        {
            return 0;
        }

        std::vector<std::byte> sign(const KeyPairHandlePtr handle, gsl::span<std::byte> hash)
        {
            return {};
        }

        int verify(const KeyPairHandlePtr handle, gsl::span<std::byte> hash, gsl::span<std::byte> signature)
        {
            return 0;
        }

        int get_key(const KeyPairHandlePtr handle, std::vector<std::byte> &vk_out)
        {
            return 0;
        }

        bool is_safe_storage_supported(SignatureAlgorithm algorithm)
        {
            return false;
        }

        void release_key(const KeyPairHandlePtr handle)
        {
        }

        std::string get_error()
        {
            return {};
        }
    }
}
