// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t, getenv
#include <string.h> // strnlen

#include <openssl/ossl_typ.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>

int go_openssl_thread_setup(void);
void go_openssl_load_functions(void* handle, const void* v1_0_sentinel, const void* v1_sentinel);

// x.x.x, considering the max number of decimal digits for each component
#define MaxVersionStringLength 32
#define OPENSSL_VERSION_3_0_RTM 0x30000000L
#define OPENSSL_VERSION_1_1_1_RTM 0x10101000L
#define OPENSSL_VERSION_1_1_0_RTM 0x10100000L
#define OPENSSL_VERSION_1_0_2_RTM 0x10002000L

#define API_EXISTS(func) (_g_##func != NULL)


#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_3_0_RTM
typedef void* EVP_MAC;
typedef void* EVP_MAC_CTX;
typedef void* OSSL_PARAM_BLD;
typedef struct ossl_param_st {
    const char *key;     
    unsigned int data_type; 
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;
#define EVP_PKEY_KEYPAIR
#endif

#include "openssl_funcs.h"

// Define pointers to all the used OpenSSL functions.
// Calling C function pointers from Go is currently not supported.
// It is possible to circumvent this by using a C function wrapper.
// https://pkg.go.dev/cmd/cgo
#define DEFINEFUNC(ret, func, args, argscall)      \
    extern ret (*_g_##func)args;                   \
    static inline ret go_openssl_##func args  \
    {                                              \
        return _g_##func argscall;                 \
    }
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_0
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED


#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L
#define OPENSSL_INIT_ADD_ALL_CIPHERS 0x00000004L
#define OPENSSL_INIT_ADD_ALL_DIGESTS 0x00000008L
#define OPENSSL_INIT_LOAD_CONFIG 0x00000040L
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#endif

// This wrapper allocate out_len on the C stack, and check that it matches the expected
// value, to avoid having to pass a pointer from Go, which would escape to the heap.
static inline void
go_openssl_EVP_EncryptUpdate_wrapper(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, size_t in_len)
{
    int len;
    go_openssl_EVP_EncryptUpdate(ctx, out, &len, in, in_len);
}
