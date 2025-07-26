// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss-openssl/utils/utils.h"
#include <openssl/core.h>
#include <openssl/types.h>
#include <memory>
#include <mpss/mpss.h>
#include <optional>
#include <string>
#include <string_view>

namespace mpss_openssl::provider {
    struct mpss_key {
        std::unique_ptr<mpss::KeyPair> key_pair = nullptr;
        std::optional<::mpss_openssl::utils::neat_string> name = std::nullopt;
        std::optional<std::string> mpss_algorithm = std::nullopt;
        std::optional<std::string> alg_name = std::nullopt;
        std::optional<std::string> sig_name = std::nullopt;
        std::optional<std::string> group_name = std::nullopt;
        std::optional<std::string> hash_name = std::nullopt;

        mpss_key(std::string_view key_name, std::optional<std::string> &mpss_algorithm);

        ~mpss_key();

        [[nodiscard]] bool has_valid_key() const noexcept;
    };

    extern const OSSL_ALGORITHM mpss_keymgmt_algorithms[];

    int mpss_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg);
} // namespace mpss_openssl::provider
