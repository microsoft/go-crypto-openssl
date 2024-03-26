# Purpose: Makefile for building the C code for CodeQL analysis.
build:
	cc openssl/goopenssl.c openssl/openssl_lock_setup.c -ldl