// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/key_reference.h"
#include "mpss/utils/ossl_ptr.h"
#include <cstddef>
#include <cstring>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>

namespace mpss::tests
{

// Wire-format fixtures built independently of the production ASN.1 templates.
[[nodiscard]]
inline std::string der_value(int tag, std::string_view content, bool constructed = false,
                             int tag_class = V_ASN1_UNIVERSAL)
{
    const int size = ASN1_object_size(constructed ? 1 : 0, static_cast<int>(content.size()), tag);
    std::string result(static_cast<std::size_t>(size), '\0');
    auto *cursor = reinterpret_cast<unsigned char *>(result.data());
    ASN1_put_object(&cursor, constructed ? 1 : 0, static_cast<int>(content.size()), tag, tag_class);
    if (!content.empty())
    {
        std::memcpy(cursor, content.data(), content.size());
    }

    return result;
}

[[nodiscard]]
inline std::string oid_der(int nid)
{
    const ASN1_OBJECT *object = OBJ_nid2obj(nid);
    return der_value(V_ASN1_OBJECT, {reinterpret_cast<const char *>(OBJ_get0_data(object)),
                                     static_cast<std::size_t>(OBJ_length(object))});
}

// AlgorithmIdentifier contents naming an EC group.
[[nodiscard]]
inline std::string ec_algorithm(int group_nid)
{
    return oid_der(NID_X9_62_id_ecPublicKey) + oid_der(group_nid);
}

// SubjectPublicKeyInfo with the given AlgorithmIdentifier contents and an octet-aligned public key.
[[nodiscard]]
inline std::string spki_der(std::string_view algorithm, std::string_view public_key)
{
    return der_value(V_ASN1_SEQUENCE,
                     der_value(V_ASN1_SEQUENCE, algorithm, true) +
                         der_value(V_ASN1_BIT_STRING, '\0' + std::string{public_key}),
                     true);
}

[[nodiscard]]
inline std::string public_key_der(EVP_PKEY *key)
{
    unsigned char *data = nullptr;
    const int size = i2d_PUBKEY(key, &data);
    const mpss::utils::openssl_buf_ptr<unsigned char> owner(data);
    return 0 < size ? std::string{reinterpret_cast<const char *>(data), static_cast<std::size_t>(size)} : std::string{};
}

// Version 1 reference: version, backend, name, [0] EXPLICIT device OPTIONAL, then the SPKI.
[[nodiscard]]
inline std::string reference_der(const KeyReference &reference, std::string_view spki)
{
    std::string fields = der_value(V_ASN1_INTEGER, std::string_view{"\x01", 1}) +
                         der_value(V_ASN1_UTF8STRING, reference.location.backend_name) +
                         der_value(V_ASN1_UTF8STRING, reference.location.name);
    if (reference.location.device_id)
    {
        fields +=
            der_value(0, der_value(V_ASN1_UTF8STRING, *reference.location.device_id), true, V_ASN1_CONTEXT_SPECIFIC);
    }

    fields += spki;
    return der_value(V_ASN1_SEQUENCE, fields, true);
}

[[nodiscard]]
inline std::string reference_der(const KeyReference &reference, EVP_PKEY *key)
{
    return reference_der(reference, public_key_der(key));
}

} // namespace mpss::tests
