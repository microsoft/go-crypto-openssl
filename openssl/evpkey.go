// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"unsafe"
)

func generateEVPPKey(id C.int, bits int, curve string) (*C.EVP_PKEY, error) {
	if (bits == 0 && curve == "") || (bits != 0 && curve != "") {
		panic("openssl: incorrect generateEVPPKey parameters")
	}
	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(id, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new_id failed")
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if C.go_openssl_EVP_PKEY_keygen_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_keygen_init failed")
	}
	if bits != 0 {
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, id, -1, C.EVP_PKEY_CTRL_RSA_KEYGEN_BITS, C.int(bits), nil) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
	}
	if curve != "" {
		nid, err := curveNID(curve)
		if err != nil {
			return nil, err
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, id, -1, C.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, nil) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
	}
	var pkey *C.EVP_PKEY
	if C.go_openssl_EVP_PKEY_keygen(ctx, &pkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_keygen failed")
	}
	return pkey, nil
}

type withKeyFunc func(func(*C.EVP_PKEY) C.int) C.int
type initFunc func(*C.EVP_PKEY_CTX) C.int
type cryptFunc func(*C.EVP_PKEY_CTX, *C.uint8_t, *C.uint, *C.uint8_t, C.uint) C.int

func setupEVP(withKey withKeyFunc, padding C.int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc) (ctx *C.EVP_PKEY_CTX, err error) {
	defer func() {
		if err != nil {
			if ctx != nil {
				C.go_openssl_EVP_PKEY_CTX_free(ctx)
				ctx = nil
			}
		}
	}()

	withKey(func(pkey *C.EVP_PKEY) C.int {
		ctx = C.go_openssl_EVP_PKEY_CTX_new(pkey, nil)
		return 1
	})
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new failed")
	}
	if init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_operation_init failed")
	}
	if padding != 0 {
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PADDING, padding, nil) != 1 {
			return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
		}
	}
	switch padding {
	case C.RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
		clabel := (*C.uint8_t)(C.malloc(C.size_t(len(label))))
		if clabel == nil {
			return nil, fail("OPENSSL_malloc")
		}
		copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_OAEP_LABEL, C.int(len(label)), unsafe.Pointer(clabel)) != 1 {
			return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
		}
	case C.RSA_PKCS1_PSS_PADDING:
		if saltLen != 0 {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PSS_SALTLEN, C.int(saltLen), nil) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_set_rsa_pss_saltlen failed")
			}
		}
		md := cryptoHashToMD(ch)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
		}
	case C.RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			md := cryptoHashToMD(ch)
			if md == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, -1, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)) != 1 {
				return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
			}
		}
	}

	return ctx, nil
}

func cryptEVP(withKey withKeyFunc, padding C.int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc, crypt cryptFunc,
	sig, in []byte) ([]byte, error) {

	ctx, err := setupEVP(withKey, padding, h, label, saltLen, ch, init)
	if err != nil {
		return nil, err
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)

	var out []byte
	var outLen C.uint
	if sig == nil {
		if crypt(ctx, nil, &outLen, base(in), C.uint(len(in))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
		}
		out = make([]byte, outLen)
	} else {
		out = sig
		outLen = C.uint(len(sig))
	}
	if crypt(ctx, base(out), &outLen, base(in), C.uint(len(in))) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
	}
	return out[:outLen], nil
}

func evpEncrypt(withKey withKeyFunc, padding C.int, h hash.Hash, label, msg []byte) ([]byte, error) {
	encryptInit := func(ctx *C.EVP_PKEY_CTX) C.int {
		return C.go_openssl_EVP_PKEY_encrypt_init(ctx)
	}
	encrypt := func(ctx *C.EVP_PKEY_CTX, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_encrypt(ctx, out, outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, h, label, 0, 0, encryptInit, encrypt, nil, msg)
}

func evpDecrypt(withKey withKeyFunc, padding C.int, h hash.Hash, label, msg []byte) ([]byte, error) {
	decryptInit := func(ctx *C.EVP_PKEY_CTX) C.int {
		return C.go_openssl_EVP_PKEY_decrypt_init(ctx)
	}
	decrypt := func(ctx *C.EVP_PKEY_CTX, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_decrypt(ctx, out, outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, h, label, 0, 0, decryptInit, decrypt, nil, msg)
}

func evpSign(withKey withKeyFunc, padding C.int, saltLen int, h crypto.Hash, hashed []byte) ([]byte, error) {
	signtInit := func(ctx *C.EVP_PKEY_CTX) C.int {
		return C.go_openssl_EVP_PKEY_sign_init(ctx)
	}
	sign := func(ctx *C.EVP_PKEY_CTX, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_sign(ctx, out, outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, nil, nil, saltLen, h, signtInit, sign, nil, hashed)
}

func evpVerify(withKey withKeyFunc, padding C.int, saltLen int, h crypto.Hash, sig, hashed []byte) error {
	verifyInit := func(ctx *C.EVP_PKEY_CTX) C.int {
		return C.go_openssl_EVP_PKEY_verify_init(ctx)
	}
	verify := func(ctx *C.EVP_PKEY_CTX, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_verify(ctx, out, *outLen, in, inLen)
	}
	_, err := cryptEVP(withKey, padding, nil, nil, saltLen, h, verifyInit, verify, sig, hashed)
	return err
}
