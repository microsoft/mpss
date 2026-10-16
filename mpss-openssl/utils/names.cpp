// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/utils/names.h"
#include "mpss/algorithm.h"
#include "mpss/mpss.h"
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace mpss_openssl::utils
{

using namespace mpss;

namespace
{

// Removes the first alias from a colon-separated list of aliases and returns it.
[[nodiscard]]
std::string_view pop_alias(std::string_view &aliases)
{
    const std::size_t separator = aliases.find(':');
    const std::string_view alias = aliases.substr(0, separator);
    aliases.remove_prefix(std::string_view::npos == separator ? aliases.size() : separator + 1);
    return alias;
}

} // namespace

namespace unsafe
{

template <std::size_t N>
[[nodiscard]]
std::string_view get_canonical_name(std::string_view name, const std::array<const char *, N> &alias_arr)
{
    // IMPORTANT NOTE: The std::string_view this function returns IS NOT NULL-TERMINATED!
    // THIS FUNCTION IS DANGEROUS TO USE DIRECTLY.

    // The idea is that we simply find the name in the list of aliases and return
    // the first name from that list.

    if (name.empty())
    {
        return {};
    }

    for (const auto &aliases : alias_arr)
    {
        const std::string_view alias_str{aliases};

        // Now check if the name is one of the aliases in alias_str.
        for (std::string_view remaining = alias_str; !remaining.empty();)
        {
            if (name == pop_alias(remaining))
            {
                // Return the first name from the list of aliases.
                return alias_str.substr(0, alias_str.find(':'));
            }
        }
    }

    // Could not find name.
    return {};
}

} // namespace unsafe

[[nodiscard]]
std::string_view get_canonical_hash_name(std::string_view name)
{
    return unsafe::get_canonical_name(name, mpss_hash_names);
}

[[nodiscard]]
std::string_view get_canonical_sig_name(std::string_view name)
{
    return unsafe::get_canonical_name(name, mpss_sig_names);
}
[[nodiscard]]
std::string_view get_canonical_group_name(std::string_view name)
{
    return unsafe::get_canonical_name(name, mpss_group_names);
}
[[nodiscard]]
std::string_view get_canonical_algorithm_name(std::string_view name)
{
    return unsafe::get_canonical_name(name, mpss_algorithm_names);
}

template <std::size_t N>
[[nodiscard]]
bool are_aliases(std::string_view name1, std::string_view name2, const std::array<const char *, N> &alias_arr)
{
    if (name1 == name2)
    {
        return true;
    }

    // Compare the canonical names for name1 and name2.
    const std::string_view canon_name1 = unsafe::get_canonical_name(name1, alias_arr);
    const std::string_view canon_name2 = unsafe::get_canonical_name(name2, alias_arr);
    if (canon_name1.empty() || canon_name2.empty())
    {
        return false;
    }

    return (canon_name1 == canon_name2);
}

[[nodiscard]]
bool are_same_hash(std::string_view name1, std::string_view name2)
{
    return are_aliases(name1, name2, mpss_hash_names);
}
[[nodiscard]]
bool are_same_sig(std::string_view name1, std::string_view name2)
{
    return are_aliases(name1, name2, mpss_sig_names);
}
[[nodiscard]]
bool are_same_group(std::string_view name1, std::string_view name2)
{
    return are_aliases(name1, name2, mpss_group_names);
}

namespace unsafe
{

template <std::size_t N>
std::string_view try_extract_canonical_name(std::string_view str, const std::array<const char *, N> &alias_arr)
{
    // IMPORTANT NOTE: The std::string_view this function returns IS NOT NULL-TERMINATED!
    // THIS FUNCTION IS DANGEROUS TO USE DIRECTLY.

    // We try to find one of the specified names in the string. If we find
    // precisely one, return the corresponding canonical name. Otherwise, we
    // return {}.

    // This will hold the first name we find in str. If we find more than one
    // (that are not aliases), we return {}.
    std::string found_name = {};

    for (const auto &aliases : alias_arr)
    {
        // Iterate over each alias.
        for (std::string_view remaining{aliases}; !remaining.empty();)
        {
            const std::string_view alias = pop_alias(remaining);

            // Next, we try to find alias in str. Moreover, check that we find
            // just one instance of it.
            auto pos_first = str.find(alias);
            auto pos_last = str.rfind(alias);
            if ((pos_first == pos_last) && (std::string_view::npos != pos_first))
            {
                // We found a match. Check if it's the first one.
                if (found_name.empty())
                {
                    // This is the first one we found. Save it.
                    found_name = alias;
                }
                else
                {
                    // We already found a name. Check if it an alias of what
                    // we found this time.
                    if (!are_aliases(found_name, alias, alias_arr))
                    {
                        // We found a different name that is not an alias.
                        return {};
                    }
                }
            }
        }
    }

    // If we found anything, then return the canonical name for it.
    if (!found_name.empty())
    {
        return get_canonical_name(found_name, alias_arr);
    }

    // No luck.
    return {};
}

} // namespace unsafe

[[nodiscard]]
std::optional<std::string> try_get_ec_group(std::string_view str)
{
    const std::string_view group_name = unsafe::try_extract_canonical_name(str, mpss_group_names);
    return group_name.empty() ? std::nullopt : std::make_optional(std::string{group_name});
}

[[nodiscard]]
std::optional<std::string> try_get_ec_group(const std::unique_ptr<KeyPair> &key_pair)
{
    // Fail if no key is present.
    if (nullptr == key_pair)
    {
        return std::nullopt;
    }

    const AlgorithmInfo info = key_pair->algorithm_info();
    const std::string_view type_str = info.type_str;
    return try_get_ec_group(type_str);
}

[[nodiscard]]
std::optional<std::string> try_get_hash_func(std::string_view str)
{
    const std::string_view hash_name = unsafe::try_extract_canonical_name(str, mpss_hash_names);
    return hash_name.empty() ? std::nullopt : std::make_optional(std::string{hash_name});
}

[[nodiscard]]
std::optional<std::string> try_get_hash_func(const std::unique_ptr<KeyPair> &key_pair)
{
    // Fail if no key is present.
    if (nullptr == key_pair)
    {
        return std::nullopt;
    }

    const mpss::AlgorithmInfo info = key_pair->algorithm_info();
    const std::string_view type_str = info.type_str;
    return try_get_hash_func(type_str);
}

[[nodiscard]]
std::optional<std::string> try_get_signature_scheme(std::string_view str)
{
    const std::string_view sig_scheme = unsafe::try_extract_canonical_name(str, mpss_sig_names);
    return sig_scheme.empty() ? std::nullopt : std::make_optional(std::string{sig_scheme});
}

[[nodiscard]]
std::optional<std::string> try_get_signature_scheme(const std::unique_ptr<KeyPair> &key_pair)
{
    // Fail if no key is present.
    if (nullptr == key_pair)
    {
        return std::nullopt;
    }

    const mpss::AlgorithmInfo info = key_pair->algorithm_info();
    const std::string_view type_str = info.type_str;
    return try_get_signature_scheme(type_str);
}

[[nodiscard]]
std::optional<std::string> try_get_algorithm_name(std::string_view str)
{
    // Note: The output of this function does *not* indicate group information!

    // First we'll try to extract the signature scheme and hash function.
    const std::optional<std::string> sig_scheme = try_get_signature_scheme(str);
    const std::optional<std::string> hash_func = try_get_hash_func(str);

    if (!sig_scheme || !hash_func)
    {
        return std::nullopt;
    }

    // Iterate over every algorithm name in the list.
    for (const auto &alg_name : mpss_algorithm_names)
    {
        // Check that the signature scheme and hash function are in the algorithm name.
        const std::string_view canonical_sig_name = unsafe::try_extract_canonical_name(alg_name, mpss_sig_names);
        if (canonical_sig_name.empty() || (canonical_sig_name != sig_scheme.value()))
        {
            continue;
        }

        const std::string_view canonical_hash_name = unsafe::try_extract_canonical_name(alg_name, mpss_hash_names);
        if (canonical_hash_name.empty() || (canonical_hash_name != hash_func.value()))
        {
            continue;
        }

        // We have found a match! Return the algorithm name.
        return alg_name;
    }

    return std::nullopt;
}

[[nodiscard]]
std::optional<std::string> try_get_algorithm_name(const std::unique_ptr<KeyPair> &key_pair)
{
    // Note: The output of this function does *not* indicate group information!

    // Fail if no key is present.
    if (nullptr == key_pair)
    {
        return std::nullopt;
    }

    const mpss::AlgorithmInfo info = key_pair->algorithm_info();
    const std::string_view type_str = info.type_str;
    return try_get_algorithm_name(type_str);
}

[[nodiscard]]
mpss::Algorithm try_get_mpss_algorithm(std::string_view str)
{
    // This function tries to retrieve the complete mpss algorithm description,
    // which includes the signature scheme descriptor, group, and hash function.

    if (str.empty())
    {
        return mpss::Algorithm::unsupported;
    }

    // First, try get the canonical name for the algorithm.
    const std::optional<std::string> alg_name = try_get_algorithm_name(str);
    if (!alg_name)
    {
        return mpss::Algorithm::unsupported;
    }

    // Next, try to get the group name.
    const std::optional<std::string> ec_group_name = try_get_ec_group(str);
    if (!ec_group_name)
    {
        return mpss::Algorithm::unsupported;
    }

    // For each name in mpss::algorithm_info, find the canonical name and compare it with alg_name.
    for (const auto &alg_info : mpss::algorithm_info)
    {
        const std::string mpss_alg_name = try_get_algorithm_name(alg_info.second.type_str).value_or("unsupported");
        const std::string mpss_ec_group_name = try_get_ec_group(alg_info.second.type_str).value_or("unsupported");
        if (mpss_alg_name == alg_name.value() && mpss_ec_group_name == ec_group_name.value())
        {
            return alg_info.first;
        }
    }

    return mpss::Algorithm::unsupported;
}

[[nodiscard]]
std::optional<std::string> try_get_mpss_algorithm_name(std::string_view str)
{
    // This function tries to retrieve the complete mpss algorithm description,
    // which includes the signature scheme descriptor, group, and hash function.

    const mpss::Algorithm algorithm = try_get_mpss_algorithm(str);
    if (mpss::Algorithm::unsupported != algorithm)
    {
        return mpss::get_algorithm_info(algorithm).type_str;
    }
    return std::nullopt;
}

} // namespace mpss_openssl::utils
