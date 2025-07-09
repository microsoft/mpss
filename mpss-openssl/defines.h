// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/config.h"

#ifdef _MSC_VER

#ifdef MPSS_BUILD_MPSS_OPENSSL_SHARED

#if defined(MPSS_OPENSSL_EXPORTS)
#define MPSS_OPENSSL_DECOR __declspec(dllexport)
#else
#define MPSS_OPENSSL_DECOR __declspec(dllimport)
#endif

#define MPSS_OPENSSL_CALL __cdecl

#else // MPSS_BUILD_MPSS_OPENSSL_SHARED

#define MPSS_OPENSSL_DECOR
#define MPSS_OPENSSL_CALL

#endif // MPSS_BUILD_MPSS_OPENSSL_SHARED

#else // _MSC_VER

#define MPSS_OPENSSL_DECOR

#define MPSS_OPENSSL_CALL

#endif // _MSC_VER
