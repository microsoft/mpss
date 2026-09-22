// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss-openssl/provider/reference.h"
#include "mpss-openssl/utils/ossl_ptr.h"
#include <algorithm>
#include <openssl/asn1t.h>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace mpss_openssl::utils;
using namespace mpss_openssl::provider;

struct KeyLocatorAsn1
{
    ASN1_BOOLEAN use_defaults;
    ASN1_UTF8STRING *backend;
    ASN1_UTF8STRING *name;
    ASN1_UTF8STRING *device;
};

ASN1_SEQUENCE(KeyLocatorAsn1) = {
    ASN1_SIMPLE(KeyLocatorAsn1, use_defaults, ASN1_BOOLEAN), ASN1_SIMPLE(KeyLocatorAsn1, backend, ASN1_UTF8STRING),
    ASN1_SIMPLE(KeyLocatorAsn1, name, ASN1_UTF8STRING),
    ASN1_EXP_OPT(KeyLocatorAsn1, device, ASN1_UTF8STRING, 0)} ASN1_SEQUENCE_END(KeyLocatorAsn1);

// Explicit tagging distinguishes internal store requests from persisted references.
using KeyLocatorRequestAsn1 = KeyLocatorAsn1;
ASN1_ITEM_TEMPLATE(KeyLocatorRequestAsn1) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_EXPLICIT, 0, KeyLocatorRequestAsn1,
                                                                  KeyLocatorAsn1)
    ASN1_ITEM_TEMPLATE_END(KeyLocatorRequestAsn1);
IMPLEMENT_ASN1_FUNCTIONS(KeyLocatorRequestAsn1);

using LocatorPtr = std::unique_ptr<KeyLocatorRequestAsn1, fn_deleter<KeyLocatorRequestAsn1_free>>;

bool valid_text(std::string_view text, std::size_t limit, bool allow_empty = false)
{
    return (allow_empty || !text.empty()) && limit >= text.size() &&
           std::ranges::all_of(text, [](unsigned char c) { return 0x20 <= c && 0x7e >= c; });
}

bool valid_location(const mpss::KeyLocation &location, bool use_defaults)
{
    return valid_text(location.backend_name, 64, use_defaults) && valid_text(location.name, 64) &&
           (!location.device_id || (!use_defaults && valid_text(*location.device_id, 256)));
}

std::string_view text_value(const ASN1_UTF8STRING *value)
{
    if (nullptr == value || 0 >= ASN1_STRING_length(value))
    {
        return {};
    }
    return {reinterpret_cast<const char *>(ASN1_STRING_get0_data(value)),
            static_cast<std::size_t>(ASN1_STRING_length(value))};
}

bool encode_locator(const KeyLocatorRequestAsn1 *value, byte_vector &out)
{
    const int size = i2d_KeyLocatorRequestAsn1(value, nullptr);
    if (0 >= size || mpss_max_reference_size < static_cast<std::size_t>(size))
    {
        return false;
    }
    byte_vector encoded(static_cast<std::size_t>(size));
    auto *cursor = reinterpret_cast<unsigned char *>(encoded.data());
    if (size != i2d_KeyLocatorRequestAsn1(value, &cursor))
    {
        return false;
    }
    out = std::move(encoded);
    return true;
}

bool build_locator(const mpss::KeyLocation &location, bool use_defaults, byte_vector &out)
{
    if (!valid_location(location, use_defaults))
    {
        return false;
    }
    LocatorPtr locator(KeyLocatorRequestAsn1_new());
    if (!locator ||
        1 != ASN1_STRING_set(locator->backend, location.backend_name.data(),
                             static_cast<int>(location.backend_name.size())) ||
        1 != ASN1_STRING_set(locator->name, location.name.data(), static_cast<int>(location.name.size())))
    {
        return false;
    }
    if (location.device_id)
    {
        locator->device = ASN1_UTF8STRING_new();
        if (nullptr == locator->device || 1 != ASN1_STRING_set(locator->device, location.device_id->data(),
                                                               static_cast<int>(location.device_id->size())))
        {
            return false;
        }
    }
    locator->use_defaults = use_defaults ? 0xff : 0;
    return encode_locator(locator.get(), out);
}

} // namespace

namespace mpss_openssl::provider
{

bool mpss_build_key_load_reference(std::string_view backend, std::string_view key_name, utils::byte_vector &reference)
{
    return build_locator(mpss::KeyLocation{std::string{backend}, std::string{key_name}, std::nullopt}, true, reference);
}

bool mpss_build_key_load_reference(const mpss::KeyLocation &location, utils::byte_vector &reference)
{
    return build_locator(location, false, reference);
}

bool mpss_parse_key_load_reference(std::span<const unsigned char> reference, mpss_load_reference &parsed,
                                   mpss_reference_error &error)
{
    error = mpss_reference_error::malformed;
    if (reference.empty() || mpss_max_reference_size < reference.size())
    {
        return false;
    }
    mpss_load_reference result;
    if ((V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED) == reference.front())
    {
        auto key = mpss::impl::decode_key_reference_der(std::as_bytes(reference), error);
        if (!key)
        {
            return false;
        }
        result.kind = mpss_reference_kind::bound;
        result.key = std::move(*key);
    }
    else
    {
        const unsigned char *cursor = reference.data();
        const LocatorPtr locator(d2i_KeyLocatorRequestAsn1(nullptr, &cursor, static_cast<long>(reference.size())));
        if (!locator || cursor != reference.data() + reference.size() ||
            (0 != locator->use_defaults && 0xff != locator->use_defaults))
        {
            return false;
        }
        byte_vector canonical;
        if (!encode_locator(locator.get(), canonical) || !std::ranges::equal(std::as_bytes(reference), canonical))
        {
            return false;
        }
        const bool use_defaults = 0 != locator->use_defaults;
        result.kind = use_defaults ? mpss_reference_kind::default_locator : mpss_reference_kind::locator;
        result.key.location.backend_name = text_value(locator->backend);
        result.key.location.name = text_value(locator->name);
        if (nullptr != locator->device)
        {
            result.key.location.device_id = text_value(locator->device);
        }
        if (!valid_location(result.key.location, use_defaults))
        {
            return false;
        }
    }
    parsed = std::move(result);
    return true;
}

} // namespace mpss_openssl::provider
