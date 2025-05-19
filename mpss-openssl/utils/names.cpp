// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/names.h"
#include <cstddef>
#include <memory>
#include <mpss/mpss.h>
#include <optional>
#include <regex>
#include <string>
#include <string_view>

namespace mpss_openssl::utils {
    using namespace mpss;

#define MPSS_NAME_CHARS R"(-_.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ)"

    namespace unsafe {
        template <std::size_t N>
        [[nodiscard]] std::string_view get_canonical_name(
            std::string_view name, const std::array<const char *, N> &alias_arr)
        {
            // IMPORTANT NOTE: The std::string_view this function returns IS NOT NULL-TERMINATED!
            // THIS FUNCTION IS DANGEROUS TO USE DIRECTLY.

            // The idea is that we simply find the name in the list of aliases and return
            // the first name from that list.

            if (name.empty()) {
                return {};
            }

            // Check that the name only contains valid characters. Notably,
            // the colon is not included in this list since it separates the aliases.
            if (name.find_first_not_of(MPSS_NAME_CHARS) != std::string_view::npos) {
                return {};
            }

            // Create a regex that matches the name in an alias string.
            std::regex name_regex(R"((?:^|:))" + std::string(name) + R"((?:$|:))");

            for (const auto &aliases : alias_arr) {
                std::string_view alias_str(aliases);

                // Now check if the hash name is a match in alias_str.
                std::match_results<std::string_view::const_iterator> match;
                if (std::regex_search(alias_str.begin(), alias_str.end(), match, name_regex)) {
                    // Return the first name from the list of aliases.
                    return alias_str.substr(0, alias_str.find(':'));
                }
            }

            // Could not find name.
            return {};
        }
    } // namespace unsafe

    [[nodiscard]] std::string_view get_canonical_hash_name(std::string_view name)
    {
        return unsafe::get_canonical_name(name, mpss_hash_names);
    }

    [[nodiscard]] std::string_view get_canonical_sig_name(std::string_view name)
    {
        return unsafe::get_canonical_name(name, mpss_sig_names);
    }
    [[nodiscard]] std::string_view get_canonical_group_name(std::string_view name)
    {
        return unsafe::get_canonical_name(name, mpss_group_names);
    }
    [[nodiscard]] std::string_view get_canonical_algorithm_name(std::string_view name)
    {
        return unsafe::get_canonical_name(name, mpss_algorithm_names);
    }

    template <std::size_t N>
    [[nodiscard]] bool are_aliases(
        std::string_view name1,
        std::string_view name2,
        const std::array<const char *, N> &alias_arr)
    {
        if (name1 == name2) {
            return true;
        }

        // Compare the canonical names for name1 and name2.
        std::string_view canon_name1 = unsafe::get_canonical_name(name1, alias_arr);
        std::string_view canon_name2 = unsafe::get_canonical_name(name2, alias_arr);
        if (canon_name1.empty() || canon_name2.empty()) {
            return false;
        }

        return (canon_name1 == canon_name2);
    }

    [[nodiscard]] bool are_same_hash(std::string_view name1, std::string_view name2)
    {
        return are_aliases(name1, name2, mpss_hash_names);
    }
    [[nodiscard]] bool are_same_sig(std::string_view name1, std::string_view name2)
    {
        return are_aliases(name1, name2, mpss_sig_names);
    }
    [[nodiscard]] bool are_same_group(std::string_view name1, std::string_view name2)
    {
        return are_aliases(name1, name2, mpss_group_names);
    }

    namespace unsafe {
        template <std::size_t N>
        std::string_view try_extract_canonical_name(
            std::string_view str, const std::array<const char *, N> &alias_arr)
        {
            // IMPORTANT NOTE: The std::string_view this function returns IS NOT NULL-TERMINATED!
            // THIS FUNCTION IS DANGEROUS TO USE DIRECTLY.

            // We try to find one of the specified names in the string. If we find
            // precisely one, return the corresponding canonical name. Otherwise, we
            // return {}.

            // This will hold the first name we find in str. If we find more than one
            // (that are not aliases), we return {}.
            std::string found_name = {};

            // Create a regex that matches all of the hash name aliases.
            std::regex name_regex(R"([)" MPSS_NAME_CHARS R"(]+)");

            for (const auto &aliases : alias_arr) {
                std::string_view alias_str(aliases);

                // Iterate over each alias.
                auto it_begin = std::regex_iterator(alias_str.begin(), alias_str.end(), name_regex);
                auto it_end = decltype(it_begin)();

                for (auto it = it_begin; it != it_end; ++it) {
                    std::string alias = it->str();

                    // Next, we try to find alias in str. Moreover, check that we find
                    // just one instance of it.
                    auto pos_first = str.find(alias);
                    auto pos_last = str.rfind(alias);
                    if ((pos_first == pos_last) && (pos_first != std::string_view::npos)) {
                        // We found a match. Check if it's the first one.
                        if (found_name.empty()) {
                            // This is the first one we found. Save it.
                            found_name = alias;
                        } else {
                            // We already found a name. Check if it an alias of what
                            // we found this time.
                            if (!are_aliases(found_name, alias, alias_arr)) {
                                // We found a different name that is not an alias.
                                return {};
                            }
                        }
                    }
                }
            }

            // If we found anything, then return the canonical name for it.
            if (!found_name.empty()) {
                return get_canonical_name(found_name, alias_arr);
            }

            // No luck.
            return {};
        }
    } // namespace unsafe

    [[nodiscard]] std::optional<std::string> try_get_ec_group(
        const std::unique_ptr<KeyPair> &key_pair)
    {
        // Fail if no key is present.
        if (!key_pair) {
            return std::nullopt;
        }

        AlgorithmInfo info = key_pair->algorithm_info();
        std::string_view type_str = info.type_str;

        // We wrap the result in std::string. This is now guaranteed to be null-terminated.
        return std::string(unsafe::try_extract_canonical_name(type_str, mpss_group_names));
    }

    [[nodiscard]] std::optional<std::string> try_get_hash_func(
        const std::unique_ptr<KeyPair> &key_pair)
    {
        // Fail if no key is present.
        if (!key_pair) {
            return std::nullopt;
        }

        mpss::AlgorithmInfo info = key_pair->algorithm_info();
        std::string_view type_str = info.type_str;

        // We wrap the result in std::string. This is now guaranteed to be null-terminated.
        return std::string(unsafe::try_extract_canonical_name(type_str, mpss_hash_names));
    }

    [[nodiscard]] std::optional<std::string> try_get_signature_scheme(
        const std::unique_ptr<KeyPair> &key_pair)
    {
        // Fail if no key is present.
        if (!key_pair) {
            return std::nullopt;
        }

        mpss::AlgorithmInfo info = key_pair->algorithm_info();
        std::string_view type_str = info.type_str;

        // We wrap the result in std::string. This is now guaranteed to be null-terminated.
        return std::string(unsafe::try_extract_canonical_name(type_str, mpss_sig_names));
    }

    [[nodiscard]] std::optional<std::string> try_get_algorithm_name(
        const std::unique_ptr<KeyPair> &key_pair)
    {
        // Fail if no key is present.
        if (!key_pair) {
            return std::nullopt;
        }

        mpss::AlgorithmInfo info = key_pair->algorithm_info();
        std::string_view type_str = info.type_str;

        // First we'll try to extract the signature scheme and hash function.
        std::optional<std::string> sig_scheme = try_get_signature_scheme(key_pair);
        std::optional<std::string> hash_func = try_get_hash_func(key_pair);

        if (!sig_scheme || !hash_func) {
            return std::nullopt;
        }

        // Iterate over every algorithm name in the list.
        for (const auto &alg_name : mpss_algorithm_names) {
            // Check that the signature scheme and hash function are in the algorithm name.
            std::string_view canonical_sig_name =
                unsafe::try_extract_canonical_name(alg_name, mpss_sig_names);
            if (canonical_sig_name.empty() || (canonical_sig_name != sig_scheme.value())) {
                continue;
            }

            std::string_view canonical_hash_name =
                unsafe::try_extract_canonical_name(alg_name, mpss_hash_names);
            if (canonical_hash_name.empty() || (canonical_hash_name != hash_func.value())) {
                continue;
            }

            // We have found a match! Return the algorithm name.
            return alg_name;
        }

        return std::nullopt;
    }
} // namespace mpss_openssl::utils