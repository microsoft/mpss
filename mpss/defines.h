// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/config.h"

#ifdef _MSC_VER

#ifdef MPSS_CORE_IS_SHARED

#if defined(MPSS_EXPORTS)
#define MPSS_DECOR __declspec(dllexport)
#else
#define MPSS_DECOR __declspec(dllimport)
#endif

#define MPSS_CALL __cdecl

#else // MPSS_CORE_IS_SHARED

#define MPSS_DECOR
#define MPSS_CALL

#endif // MPSS_CORE_IS_SHARED

#else // _MSC_VER

#define MPSS_DECOR

#define MPSS_CALL

#endif // _MSC_VER
