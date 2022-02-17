// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

// Functions based on OpenSSL 1.1 API, used when building against/running with OpenSSL 1.0.x


#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0_RTM
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L
#define OPENSSL_INIT_ADD_ALL_CIPHERS 0x00000004L
#define OPENSSL_INIT_ADD_ALL_DIGESTS 0x00000008L
#define OPENSSL_INIT_LOAD_CONFIG 0x00000040L
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#endif