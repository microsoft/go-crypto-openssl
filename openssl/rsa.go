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
	pkey, err := generateEVPPKey(C.EVP_PKEY_RSA, bits, "")
	if err != nil {
		return bad(err)
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
	return evpVerify(pub.withKey, C.RSA_PKCS1_PSS_PADDING, saltLen, h, sig, hashed)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, C.RSA_PKCS1_PADDING, 0, h, hashed)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	if pub.withKey(func(pkey *C.EVP_PKEY) C.int {
		size := C.go_openssl_EVP_PKEY_get_size(pkey)
		if len(sig) < int(size) {
			return 0
		}
		return 1
	}) == 0 {
		return errors.New("crypto/rsa: verification error")
	}
	return evpVerify(pub.withKey, C.RSA_PKCS1_PADDING, 0, h, sig, hashed)
}
