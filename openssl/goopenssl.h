// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t, getenv
#include <string.h> // strnlen

#include "openssl_funcs.h"

#include <openssl/ossl_typ.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
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

void* _goboringcrypto_DLOPEN_OPENSSL(void);
int _goboringcrypto_OPENSSL_setup(void);

// x.x.x, considering the max number of decimal digits for each component
#define MaxVersionStringLength 32
#define OPENSSL_VERSION_3_0_RTM 0x30000000L
#define OPENSSL_VERSION_1_1_1_RTM 0x10101000L
#define OPENSSL_VERSION_1_1_0_RTM 0x10100000L
#define OPENSSL_VERSION_1_0_2_RTM 0x10002000L

#include "apibridge_1_1.h"

enum
{
    GO_NID_secp224r1 = NID_secp224r1,
    GO_NID_X9_62_prime256v1 = NID_X9_62_prime256v1,
    GO_NID_secp384r1 = NID_secp384r1,
    GO_NID_secp521r1 = NID_secp521r1,
    GO_AES_ENCRYPT = 1,
    GO_AES_DECRYPT = 0,
    GO_RSA_PKCS1_PADDING = 1,
    GO_RSA_NO_PADDING = 3,
    GO_RSA_PKCS1_OAEP_PADDING = 4,
    GO_RSA_PKCS1_PSS_PADDING = 6,
};

typedef SHA_CTX GO_SHA_CTX;
typedef SHA256_CTX GO_SHA256_CTX;
typedef SHA512_CTX GO_SHA512_CTX;
typedef EVP_MD GO_EVP_MD;
typedef HMAC_CTX GO_HMAC_CTX;
typedef BN_CTX GO_BN_CTX;
typedef BIGNUM GO_BIGNUM;
typedef EC_GROUP GO_EC_GROUP;
typedef EC_POINT GO_EC_POINT;
typedef EC_KEY GO_EC_KEY;
typedef ECDSA_SIG GO_ECDSA_SIG;
typedef RSA GO_RSA;
typedef BN_GENCB GO_BN_GENCB;
typedef EVP_PKEY GO_EVP_PKEY;
typedef EVP_PKEY_CTX GO_EVP_PKEY_CTX;

// Define pointers to all the used OpenSSL functions.
// Calling C function pointers from Go is currently not supported.
// It is possible to circumvent this by using a C function wrapper.
// https://pkg.go.dev/cmd/cgo
#define DEFINEFUNC(ret, func, args, argscall)      \
    extern ret (*_g_##func)args;                   \
    static inline ret _goboringcrypto_##func args  \
    {                                              \
        return _g_##func argscall;                 \
    }
#define DEFINEFUNC_LEGACY(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_110(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_FALLBACK(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY
#undef DEFINEFUNC_110
#undef DEFINEFUNC_RENAMED
#undef DEFINEFUNC_FALLBACK

// This wrapper allocate out_len on the C stack, and check that it matches the expected
// value, to avoid having to pass a pointer from Go, which would escape to the heap.
static inline void
_goboringcrypto_EVP_EncryptUpdate_wrapper(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, size_t in_len)
{
    int len;
    _goboringcrypto_EVP_EncryptUpdate(ctx, out, &len, in, in_len);
}
