// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

#include "goopenssl.h"

#include <dlfcn.h>
#include <stdio.h>

// Approach taken from .Net System.Security.Cryptography.Native
// https://github.com/dotnet/runtime/blob/f64246ce08fb7a58221b2b7c8e68f69c02522b0d/src/libraries/Native/Unix/System.Security.Cryptography.Native/opensslshim.c

#define DEFINEFUNC(ret, func, args, argscall)                  ret (*_g_##func)args; 
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)       DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)         DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall)              DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)              DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED(ret, func, oldfunc, args, argscall) DEFINEFUNC(ret, func, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_0
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED

// Load all the functions stored in FOR_ALL_OPENSSL_FUNCTIONS
// and assign them to their corresponding function pointer
// defined in goopenssl.h.
void
go_openssl_load_functions(void* handle, const void* v1_0_sentinel, const void* v1_sentinel)
{
    // This function could be called concurrently from different Goroutines unless correctly locked.
    // If that happen there could be a race in DEFINEFUNC_RENAMED where the global function pointer is NULL,
    // then properly loaded, then goes back to NULL right before being used (then loaded again).
    // To avoid this situation only assign the function pointer when the function has been successfully
    // loaded in tmp_ptr.
    void* tmp_ptr;

#define DEFINEFUNC(ret, func, args, argscall) \
    _g_##func = dlsym(handle, #func);         \
    if (_g_##func == NULL) { fprintf(stderr, "Cannot get required symbol " #func " from libcrypto\n"); abort(); }
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)  \
    if (v1_0_sentinel != NULL)                        \
    {                                                 \
        DEFINEFUNC(ret, func, args, argscall) \
    }
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    if (v1_sentinel != NULL)                        \
    {                                                 \
        DEFINEFUNC(ret, func, args, argscall) \
    }
#define DEFINEFUNC_1_1(ret, func, args, argscall)     \
    if (v1_0_sentinel == NULL)                        \
    {                                                 \
        DEFINEFUNC(ret, func, args, argscall) \
    }
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    if (v1_sentinel == NULL)                        \
    {                                                 \
        DEFINEFUNC(ret, func, args, argscall) \
    }
#define DEFINEFUNC_RENAMED(ret, func, oldfunc, args, argscall)                                              \
    tmp_ptr = dlsym(handle, #func);                                                                         \
    if (tmp_ptr == NULL)                                                                                    \
    {                                                                                                       \
        tmp_ptr = dlsym(handle, #oldfunc);                                                                  \
        if (tmp_ptr == NULL)                                                                                \
        {                                                                                                   \
            fprintf(stderr, "Cannot get required symbol " #func " nor " #oldfunc " from libcrypto\n");      \
            abort();                                                                                        \
        }                                                                                                   \
    }                                                                                                       \
    _g_##func = tmp_ptr;

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_0
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED
}
