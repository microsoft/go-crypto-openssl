// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

// Functions based on OpenSSL 1.1 API, used when building against/running with OpenSSL 1.0.x

void local_HMAC_CTX_free(HMAC_CTX * ctx);
HMAC_CTX* local_HMAC_CTX_new();
void local_HMAC_CTX_reset(HMAC_CTX *ctx);
const EVP_MD* local_EVP_md5_sha1(void);
int local_RSA_set0_crt_params(RSA * r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
void local_RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp);
int local_RSA_set0_key(RSA * r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int local_RSA_set0_factors(RSA * r, BIGNUM *p, BIGNUM *q);
void local_RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q);
void local_RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L
#define OPENSSL_INIT_ADD_ALL_CIPHERS 0x00000004L
#define OPENSSL_INIT_ADD_ALL_DIGESTS 0x00000008L
#define OPENSSL_INIT_LOAD_CONFIG 0x00000040L
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#endif