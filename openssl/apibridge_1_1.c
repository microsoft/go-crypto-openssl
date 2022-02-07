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
struct rsa_st
{
    int _ignored0;
    long _ignored1;
    const void* _ignored2;
    const void* _ignored3;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* dmp1;
    BIGNUM* dmq1;
    BIGNUM* iqmp;
    struct crypto_ex_data_10_st _ignored4;
    int _ignored5;
    int _ignored6;
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

const EVP_MD* local_EVP_md5_sha1(void)
{
    // MD5SHA1 is not implemented in OpenSSL 1.0.2.
    // It is implemented in higher versions but without FIPS support.
    // It is considered a deprecated digest, not approved by FIPS 140-2
    // and only used in pre-TLS 1.2, so we would rather not support it
    // if using 1.0.2 than than implement something that is not properly validated.
  return NULL;
}

int
local_RSA_set0_crt_params(RSA * r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL)
    {
        go_openssl_BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL)
    {
        go_openssl_BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL)
    {
        go_openssl_BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

void
local_RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

int
local_RSA_set0_key(RSA * r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) 
    {
        go_openssl_BN_free(r->n);
        r->n = n;
    }
    if (e != NULL)
    {
        go_openssl_BN_free(r->e);
        r->e = e;
    }
    if (d != NULL)
    {
        go_openssl_BN_clear_free(r->d);
        r->d = d;
    }

    return 1;
}

int
local_RSA_set0_factors(RSA * r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL)
    {
        go_openssl_BN_clear_free(r->p);
        r->p = p;
    }
    if (q != NULL)
    {
        go_openssl_BN_clear_free(r->q);
        r->q = q;
    }

    return 1;
}

void 
local_RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q)
{
    if (p)
        *p = rsa->p;
    if (q)
        *q = rsa->q;
}

void 
local_RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n)
        *n = rsa->n;
    if (e)
        *e = rsa->e;
    if (d)
        *d = rsa->d;
}
