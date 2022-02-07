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

var (
	ossl_PKEY_PARAM_RSA_N           = C.CString("n")
	ossl_PKEY_PARAM_RSA_E           = C.CString("e")
	ossl_PKEY_PARAM_RSA_D           = C.CString("d")
	ossl_PKEY_PARAM_RSA_FACTOR1     = C.CString("rsa-factor1")
	ossl_PKEY_PARAM_RSA_FACTOR2     = C.CString("rsa-factor2")
	ossl_PKEY_PARAM_RSA_EXPONENT1   = C.CString("rsa-exponent1")
	ossl_PKEY_PARAM_RSA_EXPONENT2   = C.CString("rsa-exponent2")
	osl_PKEY_PARAM_RSA_COEFFICIENT1 = C.CString("rsa-coefficient1")
)

// rsa_st_1_0_2 is rsa_st memory layout in OpenSSL 1.0.2.
type rsa_st_1_0_2 struct {
	_    C.int
	_    C.long
	_    unsafe.Pointer
	_    unsafe.Pointer
	n    *C.BIGNUM
	e    *C.BIGNUM
	d    *C.BIGNUM
	p    *C.BIGNUM
	q    *C.BIGNUM
	dmp1 *C.BIGNUM
	dmq1 *C.BIGNUM
	iqmp *C.BIGNUM
	// It contains more fields, but we are not interesed on them.
}

func rsa_st_set_key(key *C.RSA, n, e, d *C.BIGNUM) {
	if vMajor != 1 {
		panic("openssl: rsa_st_set_key should only be used with OpenSSL 1.x")
	}
	if vMinor == 0 {
		key1_0_2 := (*rsa_st_1_0_2)(unsafe.Pointer(key))
		key1_0_2.n = n
		key1_0_2.e = e
		key1_0_2.d = d
	} else {
		C.go_openssl_RSA_set0_key(key, n, e, d)
	}
}

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	pkey, err := generateEVPPKey(C.EVP_PKEY_RSA, bits, "")
	if err != nil {
		return bad(err)
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)

	var n, e, d, p, q, dp, dq, qinv *C.BIGNUM
	switch vMajor {
	case 1:
		key := C.go_openssl_EVP_PKEY_get1_RSA(pkey)
		if key == nil {
			return bad(newOpenSSLError("EVP_PKEY_get1_RSA failed"))
		}
		defer C.go_openssl_RSA_free(key)
		if vMinor == 0 {
			key1_0_2 := (*rsa_st_1_0_2)(unsafe.Pointer(key))
			n = key1_0_2.n
			e = key1_0_2.e
			d = key1_0_2.d
			p = key1_0_2.p
			q = key1_0_2.q
			dp = key1_0_2.dmp1
			dq = key1_0_2.dmq1
			qinv = key1_0_2.iqmp
		} else {
			C.go_openssl_RSA_get0_key(key, &n, &e, &d)
			C.go_openssl_RSA_get0_factors(key, &p, &q)
			C.go_openssl_RSA_get0_crt_params(key, &dp, &dq, &qinv)
		}
	case 3:
		params := [...]struct {
			key *C.char
			bn  **C.BIGNUM
		}{
			{ossl_PKEY_PARAM_RSA_N, &n}, {ossl_PKEY_PARAM_RSA_E, &e}, {ossl_PKEY_PARAM_RSA_D, &d},
			{ossl_PKEY_PARAM_RSA_FACTOR1, &p}, {ossl_PKEY_PARAM_RSA_FACTOR2, &q},
			{ossl_PKEY_PARAM_RSA_EXPONENT1, &dp}, {ossl_PKEY_PARAM_RSA_EXPONENT2, &dq},
			{osl_PKEY_PARAM_RSA_COEFFICIENT1, &qinv},
		}
		for _, p := range params {
			if C.go_openssl_EVP_PKEY_get_bn_param(pkey, p.key, p.bn) != 1 {
				return bad(newOpenSSLError("EVP_PKEY_get_bn_param failed"))
			}
			// EVP_PKEY_get_bn_param allocates a copy of the BIGNUMBER.
			defer C.go_openssl_BN_free(*p.bn)
		}
	default:
		panic(errUnsuportedVersion())
	}
	return bnToBig(n), bnToBig(e), bnToBig(d), bnToBig(p), bnToBig(q), bnToBig(dp), bnToBig(dq), bnToBig(qinv), nil
}

type PublicKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey *C.EVP_PKEY
}

func NewPublicKeyRSA(N, E *big.Int) (*PublicKeyRSA, error) {
	var pkey *C.EVP_PKEY
	switch vMajor {
	case 1:
		key := C.go_openssl_RSA_new()
		if key == nil {
			return nil, newOpenSSLError("RSA_new failed")
		}
		n := bigToBN(N)
		e := bigToBN(E)
		rsa_st_set_key(key, n, e, nil)
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			C.go_openssl_RSA_free(key)
			return nil, newOpenSSLError("EVP_PKEY_new failed")
		}
		if C.go_openssl_EVP_PKEY_assign(pkey, C.EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
			C.go_openssl_RSA_free(key)
			C.go_openssl_EVP_PKEY_free(pkey)
			return nil, newOpenSSLError("EVP_PKEY_assign failed")
		}
	case 3:
		var err error
		pkey, err = newEVPPKey(C.EVP_PKEY_RSA, nil, nil, map[*C.char]*big.Int{
			ossl_PKEY_PARAM_RSA_N: N,
			ossl_PKEY_PARAM_RSA_E: E,
		})
		if err != nil {
			return nil, err
		}
	default:
		panic(errUnsuportedVersion())
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
	var pkey *C.EVP_PKEY
	switch vMajor {
	case 1:
		key := C.go_openssl_RSA_new()
		if key == nil {
			return nil, newOpenSSLError("RSA_new failed")
		}
		var n, e, d, p, q, dp, dq, qinv *C.BIGNUM
		n = bigToBN(N)
		e = bigToBN(E)
		d = bigToBN(D)
		rsa_st_set_key(key, n, e, d)
		if P != nil && Q != nil {
			p = bigToBN(P)
			q = bigToBN(Q)
			if vMinor == 0 {
				key1_0_2 := (*rsa_st_1_0_2)(unsafe.Pointer(key))
				key1_0_2.p = p
				key1_0_2.q = q
			} else {
				C.go_openssl_RSA_set0_factors(key, p, q)
			}
		}
		if Dp != nil && Dq != nil && Qinv != nil {
			dp = bigToBN(Dp)
			dq = bigToBN(Dq)
			qinv = bigToBN(Qinv)
			if vMinor == 0 {
				key1_0_2 := (*rsa_st_1_0_2)(unsafe.Pointer(key))
				key1_0_2.dmp1 = dq
				key1_0_2.dmq1 = dq
				key1_0_2.iqmp = qinv
			} else {
				C.go_openssl_RSA_set0_crt_params(key, dp, dq, qinv)
			}
		}
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			C.go_openssl_RSA_free(key)
			return nil, newOpenSSLError("EVP_PKEY_new failed")
		}
		if C.go_openssl_EVP_PKEY_assign(pkey, C.EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
			C.go_openssl_RSA_free(key)
			C.go_openssl_EVP_PKEY_free(pkey)
			return nil, newOpenSSLError("EVP_PKEY_assign failed")
		}
	case 3:
		var err error
		pkey, err = newEVPPKey(C.EVP_PKEY_RSA, nil, nil, map[*C.char]*big.Int{
			ossl_PKEY_PARAM_RSA_N:           N,
			ossl_PKEY_PARAM_RSA_E:           E,
			ossl_PKEY_PARAM_RSA_D:           D,
			ossl_PKEY_PARAM_RSA_FACTOR1:     P,
			ossl_PKEY_PARAM_RSA_FACTOR2:     Q,
			ossl_PKEY_PARAM_RSA_EXPONENT1:   Dp,
			ossl_PKEY_PARAM_RSA_EXPONENT2:   Dq,
			osl_PKEY_PARAM_RSA_COEFFICIENT1: Qinv,
		})
		if err != nil {
			return nil, err
		}
	default:
		panic(errUnsuportedVersion())
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
		size := int(C.go_openssl_EVP_PKEY_get_size(pkey))
		if len(sig) < size {
			return 0
		}
		return 1
	}) == 0 {
		return errors.New("crypto/rsa: verification error")
	}
	return evpVerify(pub.withKey, C.RSA_PKCS1_PADDING, 0, h, sig, hashed)
}
