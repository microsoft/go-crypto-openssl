// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t

// List of all functions from the libcrypto that are used in this package.
// Forgetting to add a function here results in build failure with message reporting the function
// that needs to be added.
//
// The purpose of FOR_ALL_OPENSSL_FUNCTIONS is to define all libcrypto functions
// without depending on the openssl headers so it is easier to use this package
// with an openssl version different that the one used at build time.
//
// The following macros may not be defined at this point,
// they are not resolved here but just accumulated in FOR_ALL_OPENSSL_FUNCTIONS.
//
// DEFINEFUNC defines and loads openssl functions that can be directly called from Go as their signatures match
// the OpenSSL API and do not require special logic.
// The process will be aborted if the function can't be loaded.
//
// DEFINEFUNC_LEGACY_1_0 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.0.x. This indicates the function is required when using 1.0.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_LEGACY_1 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.x. This indicates the function is required when using 1.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_1_1 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 1.1.0 or higher.
//
// DEFINEFUNC_3_0 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 3.0.0 or higher.
//
// DEFINEFUNC_RENAMED acts like DEFINEFUNC but if the function can't be loaded it will try with another
// function name, as in some version jumps openssl has renamed functions without changing the signature.
// The process will be aborted if neither function can be loaded.
//
#define FOR_ALL_OPENSSL_FUNCTIONS \
DEFINEFUNC(unsigned long, ERR_get_error, (void), ()) \
DEFINEFUNC(void, ERR_error_string_n, (unsigned long e, unsigned char *buf, size_t len), (e, buf, len)) \
DEFINEFUNC_RENAMED(const char *, OpenSSL_version, SSLeay_version, (int type), (type)) \
DEFINEFUNC(void, OPENSSL_init, (void), ()) \
DEFINEFUNC_LEGACY_1_0(void, ERR_load_crypto_strings, (void), ()) \
DEFINEFUNC_LEGACY_1_0(int, CRYPTO_num_locks, (void), ()) \
DEFINEFUNC_LEGACY_1_0(void, CRYPTO_set_id_callback, (unsigned long (*id_function)(void)), (id_function)) \
DEFINEFUNC_LEGACY_1_0(void, CRYPTO_set_locking_callback, \
    (void (*locking_function)(int mode, int n, const char *file, int line)),  \
    (locking_function)) \
DEFINEFUNC_LEGACY_1_0(void, OPENSSL_add_all_algorithms_conf, (void), ()) \
DEFINEFUNC_1_1(int, OPENSSL_init_crypto, (uint64_t ops, const void *settings), (ops, settings)) \
DEFINEFUNC(int, FIPS_mode, (void), ()) \
DEFINEFUNC(int, FIPS_mode_set, (int r), (r)) \
DEFINEFUNC(int, RAND_bytes, (uint8_t * arg0, size_t arg1), (arg0, arg1)) \
DEFINEFUNC(int, EVP_DigestInit_ex, (EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl), (ctx, type, impl)) \
DEFINEFUNC(int, EVP_DigestUpdate, (EVP_MD_CTX *ctx, const void *d, size_t cnt), (ctx, d, cnt)) \
DEFINEFUNC(int, EVP_DigestFinal_ex, (EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s), (ctx, md, s)) \
DEFINEFUNC_RENAMED(EVP_MD_CTX *, EVP_MD_CTX_new, EVP_MD_CTX_create, (), ()) \
DEFINEFUNC_RENAMED(void, EVP_MD_CTX_free, EVP_MD_CTX_destroy, (EVP_MD_CTX *ctx), (ctx)) \
DEFINEFUNC(int, EVP_MD_CTX_copy_ex, (EVP_MD_CTX *out, const EVP_MD_CTX *in), (out, in)) \
DEFINEFUNC_RENAMED(int, EVP_MD_CTX_reset, EVP_MD_CTX_cleanup, (EVP_MD_CTX *ctx), (ctx)) \
DEFINEFUNC(const EVP_MD *, EVP_md5, (void), ()) \
DEFINEFUNC(const EVP_MD *, EVP_sha1, (void), ()) \
DEFINEFUNC(const EVP_MD *, EVP_sha224, (void), ()) \
DEFINEFUNC(const EVP_MD *, EVP_sha256, (void), ()) \
DEFINEFUNC(const EVP_MD *, EVP_sha384, (void), ()) \
DEFINEFUNC(const EVP_MD *, EVP_sha512, (void), ()) \
DEFINEFUNC_FALLBACK(const EVP_MD*, EVP_md5_sha1, (void), ()) \
DEFINEFUNC_RENAMED(int, EVP_MD_get_type, EVP_MD_type, (const EVP_MD *arg0), (arg0)) \
DEFINEFUNC_RENAMED(size_t, EVP_MD_get_size, EVP_MD_size, (const EVP_MD *arg0), (arg0)) \
DEFINEFUNC_LEGACY_1_0(void, HMAC_CTX_init, (HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC_LEGACY_1_0(void, HMAC_CTX_cleanup, (HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC(int, HMAC_Init_ex, \
           (HMAC_CTX * arg0, const void *arg1, int arg2, const EVP_MD *arg3, ENGINE *arg4), \
           (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, HMAC_Update, (HMAC_CTX * arg0, const uint8_t *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, HMAC_Final, (HMAC_CTX * arg0, uint8_t *arg1, unsigned int *arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(size_t, HMAC_CTX_copy, (HMAC_CTX *dest, HMAC_CTX *src), (dest, src)) \
DEFINEFUNC_FALLBACK(void, HMAC_CTX_free, (HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC_FALLBACK(HMAC_CTX*, HMAC_CTX_new, (void), ()) \
DEFINEFUNC_FALLBACK(void, HMAC_CTX_reset, (HMAC_CTX * arg0), (arg0)) \
DEFINEFUNC(EVP_CIPHER_CTX *, EVP_CIPHER_CTX_new, (void), ()) \
DEFINEFUNC(int, EVP_CIPHER_CTX_set_padding, (EVP_CIPHER_CTX *x, int padding), (x, padding)) \
DEFINEFUNC(int, EVP_CipherInit_ex, \
           (EVP_CIPHER_CTX * ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc), \
           (ctx, type, impl, key, iv, enc)) \
DEFINEFUNC(int, EVP_CipherUpdate, \
           (EVP_CIPHER_CTX * ctx, unsigned char *out, int *outl, const unsigned char *in, int inl), \
           (ctx, out, outl, in, inl)) \
DEFINEFUNC(BIGNUM *, BN_new, (void), ()) \
DEFINEFUNC(void, BN_free, (BIGNUM * arg0), (arg0)) \
DEFINEFUNC(void, BN_clear_free, (BIGNUM * arg0), (arg0)) \
DEFINEFUNC(unsigned int, BN_num_bits, (const BIGNUM *arg0), (arg0)) \
DEFINEFUNC(BIGNUM *, BN_bin2bn, (const uint8_t *arg0, size_t arg1, BIGNUM *arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(size_t, BN_bn2bin, (const BIGNUM *arg0, uint8_t *arg1), (arg0, arg1)) \
DEFINEFUNC(void, EC_GROUP_free, (EC_GROUP * arg0), (arg0)) \
DEFINEFUNC(EC_POINT *, EC_POINT_new, (const EC_GROUP *arg0), (arg0)) \
DEFINEFUNC(void, EC_POINT_free, (EC_POINT * arg0), (arg0)) \
DEFINEFUNC(int, EC_POINT_get_affine_coordinates_GFp, \
           (const EC_GROUP *arg0, const EC_POINT *arg1, BIGNUM *arg2, BIGNUM *arg3, BN_CTX *arg4), \
           (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(EC_KEY *, EC_KEY_new_by_curve_name, (int arg0), (arg0)) \
DEFINEFUNC(int, EC_KEY_set_public_key_affine_coordinates, (EC_KEY *key, BIGNUM *x, BIGNUM *y), (key, x, y)) \
DEFINEFUNC(void, EC_KEY_free, (EC_KEY * arg0), (arg0)) \
DEFINEFUNC(const EC_GROUP *, EC_KEY_get0_group, (const EC_KEY *arg0), (arg0)) \
DEFINEFUNC(int, EC_KEY_set_private_key, (EC_KEY * arg0, const BIGNUM *arg1), (arg0, arg1)) \
DEFINEFUNC(const BIGNUM *, EC_KEY_get0_private_key, (const EC_KEY *arg0), (arg0)) \
DEFINEFUNC(const EC_POINT *, EC_KEY_get0_public_key, (const EC_KEY *arg0), (arg0)) \
DEFINEFUNC(RSA *, RSA_new, (void), ()) \
DEFINEFUNC(void, RSA_free, (RSA * arg0), (arg0)) \
DEFINEFUNC_FALLBACK(int, RSA_set0_factors, (RSA * rsa, BIGNUM *p, BIGNUM *q), (rsa, p, q)) \
DEFINEFUNC_FALLBACK(int, RSA_set0_crt_params, \
    (RSA * rsa, BIGNUM *dmp1, BIGNUM *dmp2, BIGNUM *iqmp), \
    (rsa, dmp1, dmp2, iqmp)) \
DEFINEFUNC_FALLBACK(void, RSA_get0_crt_params, \
    (const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp), \
    (r, dmp1, dmq1, iqmp)) \
DEFINEFUNC_FALLBACK(int, RSA_set0_key, (RSA * r, BIGNUM *n, BIGNUM *e, BIGNUM *d), (r, n, e, d)) \
DEFINEFUNC_FALLBACK(void, RSA_get0_factors, (const RSA *rsa, const BIGNUM **p, const BIGNUM **q), (rsa, p, q)) \
DEFINEFUNC_FALLBACK(void, RSA_get0_key, \
    (const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d), \
    (rsa, n, e, d)) \
DEFINEFUNC(int, EVP_EncryptInit_ex, \
    (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv), \
    (ctx, type, impl, key, iv)) \
DEFINEFUNC(int, EVP_EncryptUpdate, \
    (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl), \
    (ctx, out, outl, in, inl)) \
DEFINEFUNC(int, EVP_EncryptFinal_ex, \
    (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl), \
    (ctx, out, outl)) \
DEFINEFUNC(int, EVP_DecryptUpdate, \
    (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl),	(ctx, out, outl, in, inl)) \
DEFINEFUNC(int, EVP_DecryptFinal_ex, (EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl),	(ctx, outm, outl)) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_gcm, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_cbc, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_ctr, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_128_ecb, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_gcm, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_cbc, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_ctr, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_192_ecb, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_cbc, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_ctr, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_ecb, (void), ()) \
DEFINEFUNC(const EVP_CIPHER*, EVP_aes_256_gcm, (void), ()) \
DEFINEFUNC(void, EVP_CIPHER_CTX_free, (EVP_CIPHER_CTX* arg0), (arg0)) \
DEFINEFUNC(int, EVP_CIPHER_CTX_ctrl, (EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr), (ctx, type, arg, ptr)) \
DEFINEFUNC(EVP_PKEY *, EVP_PKEY_new, (void), ()) \
DEFINEFUNC_RENAMED(int, EVP_PKEY_get_size, EVP_PKEY_size, (const EVP_PKEY *pkey), (pkey)) \
DEFINEFUNC(void, EVP_PKEY_free, (EVP_PKEY * arg0), (arg0)) \
DEFINEFUNC(EC_KEY *, EVP_PKEY_get1_EC_KEY, (EVP_PKEY *pkey), (pkey)) \
DEFINEFUNC(RSA *, EVP_PKEY_get1_RSA, (EVP_PKEY *pkey), (pkey)) \
DEFINEFUNC(int, EVP_PKEY_assign, (EVP_PKEY *pkey, int type, void *key), (pkey, type, key)) \
DEFINEFUNC(int, EVP_PKEY_verify, \
    (EVP_PKEY_CTX *ctx, const uint8_t *sig, unsigned int siglen, const uint8_t *tbs, unsigned int tbslen), \
    (ctx, sig, siglen, tbs, tbslen)) \
DEFINEFUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_new, (EVP_PKEY * arg0, ENGINE *arg1), (arg0, arg1)) \
DEFINEFUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_new_id, (int id, ENGINE *e), (id, e)) \
DEFINEFUNC(int, EVP_PKEY_keygen_init, (EVP_PKEY_CTX *ctx), (ctx)) \
DEFINEFUNC(int, EVP_PKEY_keygen, (EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey), (ctx, ppkey)) \
DEFINEFUNC(void, EVP_PKEY_CTX_free, (EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_CTX_ctrl, \
    (EVP_PKEY_CTX * ctx, int keytype, int optype, int cmd, int p1, void *p2), \
    (ctx, keytype, optype, cmd, p1, p2)) \
DEFINEFUNC(int, EVP_PKEY_decrypt, \
    (EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4), \
    (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EVP_PKEY_encrypt, \
    (EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4), \
    (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EVP_PKEY_decrypt_init, (EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_encrypt_init, (EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_sign_init, (EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_verify_init, (EVP_PKEY_CTX * arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_sign, \
    (EVP_PKEY_CTX * arg0, uint8_t *arg1, unsigned int *arg2, const uint8_t *arg3, unsigned int arg4), \
    (arg0, arg1, arg2, arg3, arg4))
