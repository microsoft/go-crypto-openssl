// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"math/big"
	"runtime"
	"unsafe"
)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}

	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.EVP_PKEY_RSA, nil)
	if ctx == nil {
		return bad(newOpenSSLError("EVP_PKEY_CTX_new_id failed"))
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)

	if C.go_openssl_EVP_PKEY_keygen_init(ctx) != 1 {
		return bad(newOpenSSLError("EVP_PKEY_keygen_init failed"))
	}

	if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, C.EVP_PKEY_OP_KEYGEN, C.EVP_PKEY_CTRL_RSA_KEYGEN_BITS, C.int(bits), nil) != 1 {
		return bad(newOpenSSLError("EVP_PKEY_CTX_ctrl failed"))
	}

	var pkey *C.EVP_PKEY
	if C.go_openssl_EVP_PKEY_keygen(ctx, &pkey) != 1 {
		return bad(newOpenSSLError("EVP_PKEY_keygen failed"))
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)

	key := C.go_openssl_EVP_PKEY_get1_RSA(pkey)
	if key == nil {
		return bad(newOpenSSLError("EVP_PKEY_get1_RSA failed"))
	}

	var n, e, d, p, q, dp, dq, qinv *C.BIGNUM
	C.go_openssl_RSA_get0_key(key, &n, &e, &d)
	C.go_openssl_RSA_get0_factors(key, &p, &q)
	C.go_openssl_RSA_get0_crt_params(key, &dp, &dq, &qinv)
	return bnToBig(n), bnToBig(e), bnToBig(d), bnToBig(p), bnToBig(q), bnToBig(dp), bnToBig(dq), bnToBig(qinv), nil
}

type PublicKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey *C.EVP_PKEY
}

func NewPublicKeyRSA(N, E *big.Int) (*PublicKeyRSA, error) {
	key := C.go_openssl_RSA_new()
	if key == nil {
		return nil, newOpenSSLError("RSA_new failed")
	}
	var n, e *C.BIGNUM
	n = bigToBN(N)
	e = bigToBN(E)
	C.go_openssl_RSA_set0_key(key, n, e, nil)
	pkey := C.go_openssl_EVP_PKEY_new()
	if pkey == nil {
		C.go_openssl_RSA_free(key)
		return nil, newOpenSSLError("EVP_PKEY_new failed")
	}
	if C.go_openssl_EVP_PKEY_assign(pkey, C.EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
		C.go_openssl_RSA_free(key)
		C.go_openssl_EVP_PKEY_free(pkey)
		return nil, newOpenSSLError("EVP_PKEY_assign failed")
	}
	k := &PublicKeyRSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PublicKeyRSA).finalize)
	return k, nil
}

func (k *PublicKeyRSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyRSA) withKey(f func(*C.EVP_PKEY) C.int) C.int {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PrivateKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey *C.EVP_PKEY
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv *big.Int) (*PrivateKeyRSA, error) {
	key := C.go_openssl_RSA_new()
	if key == nil {
		return nil, newOpenSSLError("RSA_new failed")
	}
	var n, e, d, p, q, dp, dq, qinv *C.BIGNUM
	n = bigToBN(N)
	e = bigToBN(E)
	d = bigToBN(D)
	C.go_openssl_RSA_set0_key(key, n, e, d)
	if P != nil && Q != nil {
		p = bigToBN(P)
		q = bigToBN(Q)
		C.go_openssl_RSA_set0_factors(key, p, q)
	}
	if Dp != nil && Dq != nil && Qinv != nil {
		dp = bigToBN(Dp)
		dq = bigToBN(Dq)
		qinv = bigToBN(Qinv)
		C.go_openssl_RSA_set0_crt_params(key, dp, dq, qinv)
	}
	pkey := C.go_openssl_EVP_PKEY_new()
	if pkey == nil {
		C.go_openssl_RSA_free(key)
		return nil, newOpenSSLError("EVP_PKEY_new failed")
	}
	if C.go_openssl_EVP_PKEY_assign(pkey, C.EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
		C.go_openssl_RSA_free(key)
		C.go_openssl_EVP_PKEY_free(pkey)
		return nil, newOpenSSLError("EVP_PKEY_assign failed")
	}
	k := &PrivateKeyRSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PrivateKeyRSA).finalize)
	return k, nil
}

func (k *PrivateKeyRSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyRSA) withKey(f func(*C.EVP_PKEY) C.int) C.int {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
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
	if init(ctx) == 0 {
		return nil, newOpenSSLError("EVP_PKEY_operation_init failed")
	}
	if padding != 0 {
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PADDING, padding, nil) == 0 {
			return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
		}
	}
	switch padding {
	case C.RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, C.EVP_PKEY_OP_TYPE_CRYPT, C.EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)) == 0 {
			return nil, newOpenSSLError("EVP_PKEY_set_rsa_oaep_md failed")
		}
		// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
		clabel := (*C.uint8_t)(C.malloc(C.size_t(len(label))))
		if clabel == nil {
			return nil, fail("OPENSSL_malloc")
		}
		copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, C.EVP_PKEY_OP_TYPE_CRYPT, C.EVP_PKEY_CTRL_RSA_OAEP_LABEL, C.int(len(label)), unsafe.Pointer(clabel)) == 0 {
			return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
		}
	case C.RSA_PKCS1_PSS_PADDING:
		if saltLen != 0 {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, C.EVP_PKEY_OP_SIGN|C.EVP_PKEY_OP_VERIFY, C.EVP_PKEY_CTRL_RSA_PSS_SALTLEN, C.int(saltLen), nil) == 0 {
				return nil, newOpenSSLError("EVP_PKEY_set_rsa_pss_saltlen failed")
			}
		}
		md := cryptoHashToMD(ch)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.EVP_PKEY_OP_TYPE_SIG, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)) == 0 {
			return nil, newOpenSSLError("go_openssl_EVP_PKEY_CTX_ctrl failed")
		}
	case C.RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			md := cryptoHashToMD(ch)
			if md == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.EVP_PKEY_OP_TYPE_SIG, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)) == 0 {
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
		if crypt(ctx, nil, &outLen, base(in), C.uint(len(in))) == 0 {
			return nil, newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
		}
		out = make([]byte, outLen)
	} else {
		out = sig
		outLen = C.uint(len(sig))
	}
	if crypt(ctx, base(out), &outLen, base(in), C.uint(len(in))) <= 0 {
		return nil, newOpenSSLError("EVP_PKEY_decrypt/encrypt failed")
	}
	return out[:outLen], nil
}

func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, C.RSA_PKCS1_OAEP_PADDING, h, label, ciphertext)
}

func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, C.RSA_PKCS1_OAEP_PADDING, h, label, msg)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, C.RSA_PKCS1_PADDING, nil, nil, ciphertext)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, C.RSA_PKCS1_PADDING, nil, nil, msg)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	ret, err := evpDecrypt(priv.withKey, C.RSA_NO_PADDING, nil, nil, ciphertext)
	if err != nil {
		return nil, err
	}
	// We could return here, but the Go standard library test expects DecryptRSANoPadding to verify the result
	// in order to defend against errors in the CRT computation.
	//
	// The following code tries to replicate the verification implemented in the upstream function decryptAndCheck, found at
	// https://github.com/golang/go/blob/9de1ac6ac2cad3871760d0aa288f5ca713afd0a6/src/crypto/rsa/rsa.go#L569-L582.
	pub := &PublicKeyRSA{_pkey: priv._pkey}
	// A private EVP_PKEY can be used as a public key as it contains the public information.
	enc, err := EncryptRSANoPadding(pub, ret)
	if err != nil {
		return nil, err
	}
	// Upstream does not do a constant time comparison because it works with math/big instead of byte slices,
	// and math/big does not support constant-time arithmetic yet. See #20654 for more info.
	if subtle.ConstantTimeCompare(ciphertext, enc) != 1 {
		return nil, errors.New("rsa: internal error")
	}
	return ret, nil
}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, C.RSA_NO_PADDING, nil, nil, msg)
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

func evpVerify(withKey withKeyFunc, padding C.int, saltLen int, h crypto.Hash, sig, hashed []byte) ([]byte, error) {
	verifyInit := func(ctx *C.EVP_PKEY_CTX) C.int {
		return C.go_openssl_EVP_PKEY_verify_init(ctx)
	}
	verify := func(ctx *C.EVP_PKEY_CTX, out *C.uint8_t, outLen *C.uint, in *C.uint8_t, inLen C.uint) C.int {
		return C.go_openssl_EVP_PKEY_verify(ctx, out, *outLen, in, inLen)
	}
	return cryptEVP(withKey, padding, nil, nil, saltLen, h, verifyInit, verify, sig, hashed)
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	if saltLen == 0 {
		saltLen = -1 // RSA_PSS_SALTLEN_DIGEST
	}
	return evpSign(priv.withKey, C.RSA_PKCS1_PSS_PADDING, saltLen, h, hashed)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	if saltLen == 0 {
		saltLen = -2 // RSA_PSS_SALTLEN_AUTO
	}
	_, err := evpVerify(pub.withKey, C.RSA_PKCS1_PSS_PADDING, saltLen, h, sig, hashed)
	return err
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, C.RSA_PKCS1_PADDING, 0, h, hashed)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	if pub.withKey(func(pkey *C.EVP_PKEY) C.int {
		size := int(C.go_openssl_EVP_PKEY_get_size(pkey))
		if len(sig) < size {
			return 0
		}
		return 1
	}) == 0 {
		return errors.New("crypto/rsa: verification error")
	}
	out, err := evpVerify(pub.withKey, C.RSA_PKCS1_PADDING, 0, h, sig, hashed)
	if h == 0 {
		if subtle.ConstantTimeCompare(hashed, out) != 1 {
			return fail("VerifyRSAPKCS1v15")
		}
	}
	return err
}
