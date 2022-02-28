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

// hashToMD converts a hash.Hash implementation from this package to a GO_EVP_MD_PTR.
func hashToMD(h hash.Hash) C.GO_EVP_MD_PTR {
	switch h.(type) {
	case *sha1Hash:
		return C.go_openssl_EVP_sha1()
	case *sha224Hash:
		return C.go_openssl_EVP_sha224()
	case *sha256Hash:
		return C.go_openssl_EVP_sha256()
	case *sha384Hash:
		return C.go_openssl_EVP_sha384()
	case *sha512Hash:
		return C.go_openssl_EVP_sha512()
	}
	return nil
}

// cryptoHashToMD converts a crypto.Hash to a GO_EVP_MD_PTR.
func cryptoHashToMD(ch crypto.Hash) C.GO_EVP_MD_PTR {
	switch ch {
	case crypto.MD5:
		return C.go_openssl_EVP_md5()
	case crypto.MD5SHA1:
		if vMajor == 1 && vMinor == 0 {
			// MD5SHA1 is not implemented in OpenSSL 1.0.2.
			// It is implemented in higher versions but without FIPS support.
			// It is considered a deprecated digest, not approved by FIPS 140-2
			// and only used in pre-TLS 1.2, so we would rather not support it
			// if using 1.0.2 than than implement something that is not properly validated.
			return nil
		}
		return C.go_openssl_EVP_md5_sha1()
	case crypto.SHA1:
		return C.go_openssl_EVP_sha1()
	case crypto.SHA224:
		return C.go_openssl_EVP_sha224()
	case crypto.SHA256:
		return C.go_openssl_EVP_sha256()
	case crypto.SHA384:
		return C.go_openssl_EVP_sha384()
	case crypto.SHA512:
		return C.go_openssl_EVP_sha512()
	}
	return nil
}

func generateEVPPKey(id C.int, bits int, curve string) (C.GO_EVP_PKEY_PTR, error) {
	if (bits == 0 && curve == "") || (bits != 0 && curve != "") {
		return nil, fail("incorrect generateEVPPKey parameters")
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
	var pkey C.GO_EVP_PKEY_PTR
	if C.go_openssl_EVP_PKEY_keygen(ctx, &pkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_keygen failed")
	}
	return pkey, nil
}

type withKeyFunc func(func(C.GO_EVP_PKEY_PTR) C.int) C.int
type initFunc func(C.GO_EVP_PKEY_CTX_PTR) C.int
type cryptFunc func(C.GO_EVP_PKEY_CTX_PTR, *C.uint8_t, *C.uint, *C.uint8_t, C.uint) C.int
type verifyFunc func(C.GO_EVP_PKEY_CTX_PTR, *C.uint8_t, C.uint, *C.uint8_t, C.uint) C.int

func setupEVP(withKey withKeyFunc, padding C.int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc) (ctx C.GO_EVP_PKEY_CTX_PTR, err error) {
	defer func() {
		if err != nil {
			if ctx != nil {
				C.go_openssl_EVP_PKEY_CTX_free(ctx)
				ctx = nil
			}
		}
	}()

	withKey(func(pkey C.GO_EVP_PKEY_PTR) C.int {
		ctx = C.go_openssl_EVP_PKEY_CTX_new(pkey, nil)
		return 1
	})
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new failed")
	}
	if init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_operation_init failed")
	}
	if padding == 0 {
		return ctx, nil
	}
	// Each padding type has its own requirements in terms of when to apply the padding,
	// so it can't be just set at this point.
	setPadding := func() error {
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PADDING, padding, nil) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		return nil
	}
	switch padding {
	case C.RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		// setPadding must happen before setting EVP_PKEY_CTRL_RSA_OAEP_MD.
		if err := setPadding(); err != nil {
			return nil, err
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
		// OpenSSL 1.1.1 and higher does not take ownership of the label if the length is zero,
		// so better avoid the allocation.
		var clabel *C.uint8_t
		if len(label) > 0 {
			// Go guarantees C.malloc never returns nil.
			clabel = (*C.uint8_t)(C.malloc(C.size_t(len(label))))
			copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_OAEP_LABEL, C.int(len(label)), unsafe.Pointer(clabel)) != 1 {
			if clabel != nil {
				C.free(unsafe.Pointer(clabel))
			}
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
	case C.RSA_PKCS1_PSS_PADDING:
		md := cryptoHashToMD(ch)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		// setPadding must happen after setting EVP_PKEY_CTRL_MD.
		if err := setPadding(); err != nil {
			return nil, err
		}
		if saltLen != 0 {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PSS_SALTLEN, C.int(saltLen), nil) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
			}
		}

	case C.RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			md := cryptoHashToMD(ch)
			if md == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, -1, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
			}
			if err := setPadding(); err != nil {
				return nil, err
			}
		}
	default:
		if err := setPadding(); err != nil {
			return nil, err
		}
	}
	return ctx, nil
}

func cryptEVP(withKey withKeyFunc, padding C.int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc, crypt cryptFunc, in []byte) ([]byte, error) {

	ctx, err := setupEVP(withKey, padding, h, label, saltLen, ch, init)
	if err != nil {
		return nil, err
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	var outLen C.uint
	if crypt(ctx, nil, &outLen, base(in), C.uint(len(in))) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
	}
	out := make([]byte, outLen)
	if crypt(ctx, base(out), &outLen, base(in), C.uint(len(in))) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
	}
	return out[:outLen], nil
}

func verifyEVP(withKey withKeyFunc, padding C.int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc, verify verifyFunc,
	sig, in []byte) error {

	ctx, err := setupEVP(withKey, padding, h, label, saltLen, ch, init)
	if err != nil {
		return err
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if verify(ctx, base(sig), C.uint(len(sig)), base(in), C.uint(len(in))) != 1 {
		return newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
	}
	return nil
}

func evpEncrypt(withKey withKeyFunc, padding C.int, h hash.Hash, label, msg []byte) ([]byte, error) {
	encryptInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) C.int {
		return C.go_openssl_EVP_PKEY_encrypt_init(ctx)
	}
	encrypt := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_encrypt(ctx, out, outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, h, label, 0, 0, encryptInit, encrypt, msg)
}

func evpDecrypt(withKey withKeyFunc, padding C.int, h hash.Hash, label, msg []byte) ([]byte, error) {
	decryptInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) C.int {
		return C.go_openssl_EVP_PKEY_decrypt_init(ctx)
	}
	decrypt := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_decrypt(ctx, out, outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, h, label, 0, 0, decryptInit, decrypt, msg)
}

func evpSign(withKey withKeyFunc, padding C.int, saltLen int, h crypto.Hash, hashed []byte) ([]byte, error) {
	signtInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) C.int {
		return C.go_openssl_EVP_PKEY_sign_init(ctx)
	}
	sign := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_sign(ctx, out, outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, nil, nil, saltLen, h, signtInit, sign, hashed)
}

func evpVerify(withKey withKeyFunc, padding C.int, saltLen int, h crypto.Hash, sig, hashed []byte) error {
	verifyInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) C.int {
		return C.go_openssl_EVP_PKEY_verify_init(ctx)
	}
	verify := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uint8_t, outLen C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_verify(ctx, out, outLen, in, inLen)
	}
	return verifyEVP(withKey, padding, nil, nil, saltLen, h, verifyInit, verify, sig, hashed)
}
