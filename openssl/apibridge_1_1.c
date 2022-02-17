// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

#include "goopenssl.h"
#include "apibridge_1_1.h"

// Minimally define the structs from 1.0.x which went opaque in 1.1.0 for the
// portable build building against the 1.1.x headers
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0_RTM
// The crypto_ex_data_st struct is smaller in 1.1, which changes the packing of
// dsa_st
struct crypto_ex_data_10_st
{
    STACK_OF(void) * sk;
    int dummy;
};

struct hmac_ctx_st
{
    // 0x120 is the sizeof value when building against OpenSSL 1.0.2 on
    // Ubuntu 16.04
    unsigned char _ignored0[0x120];
};
#endif

void
local_HMAC_CTX_free(HMAC_CTX* ctx)
{
    if (ctx != NULL)
    {
        go_openssl_HMAC_CTX_cleanup(ctx);
        free(ctx);
    }
}

HMAC_CTX*
local_HMAC_CTX_new()
{
    HMAC_CTX* ctx = malloc(sizeof(HMAC_CTX));
    if (ctx)
    {
        go_openssl_HMAC_CTX_init(ctx);
    }

    return ctx;
}

void
local_HMAC_CTX_reset(HMAC_CTX* ctx) {
    go_openssl_HMAC_CTX_cleanup(ctx);
    go_openssl_HMAC_CTX_init(ctx);
}
