// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"encoding/asn1"
	"errors"
	"math/big"
	"runtime"
	"unsafe"
)

type ecdsaSignature struct {
	R, S *big.Int
}

type PrivateKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey *C.EVP_PKEY
}

func (k *PrivateKeyECDSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyECDSA) withKey(f func(*C.EVP_PKEY) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PublicKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey *C.EVP_PKEY
}

func (k *PublicKeyECDSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyECDSA) withKey(f func(*C.EVP_PKEY) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

var errUnknownCurve = errors.New("openssl: unknown elliptic curve")
var errUnsupportedCurve = errors.New("openssl: unsupported elliptic curve")

func curveNID(curve string) (C.int, error) {
	switch curve {
	case "P-224":
		return C.NID_secp224r1, nil
	case "P-256":
		return C.NID_X9_62_prime256v1, nil
	case "P-384":
		return C.NID_secp384r1, nil
	case "P-521":
		return C.NID_secp521r1, nil
	}
	return 0, errUnknownCurve
}

func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*PublicKeyECDSA, error) {
	pkey, err := newECKey(curve, X, Y, nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDSA{_pkey: pkey}
	// Note: Because of the finalizer, any time k.key is passed to cgo,
	// that call must be followed by a call to runtime.KeepAlive(k),
	// to make sure k is not collected (and finalized) before the cgo
	// call returns.
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func newECKey(curve string, X, Y, D *big.Int) (pkey *C.EVP_PKEY, err error) {
	var nid C.int
	if nid, err = curveNID(curve); err != nil {
		return nil, err
	}
	var bx, by *C.BIGNUM
	var key *C.EC_KEY
	defer func() {
		if bx != nil {
			C.go_openssl_BN_free(bx)
		}
		if by != nil {
			C.go_openssl_BN_free(by)
		}
		if err != nil {
			if key != nil {
				C.go_openssl_EC_KEY_free(key)
			}
			if pkey != nil {
				C.go_openssl_EVP_PKEY_free(pkey)
				// pkey is a named return, so in case of error
				// it have to be cleared before returing.
				pkey = nil
			}
		}
	}()
	bx = bigToBN(X)
	by = bigToBN(Y)
	if bx == nil || by == nil {
		return nil, newOpenSSLError("BN_bin2bn failed")
	}
	if key = C.go_openssl_EC_KEY_new_by_curve_name(nid); key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name failed")
	}
	if C.go_openssl_EC_KEY_set_public_key_affine_coordinates(key, bx, by) != 1 {
		return nil, newOpenSSLError("EC_KEY_set_public_key_affine_coordinates failed")
	}
	if D != nil {
		bd := bigToBN(D)
		if bd == nil {
			return nil, newOpenSSLError("BN_bin2bn failed")
		}
		defer C.go_openssl_BN_free(bd)
		if C.go_openssl_EC_KEY_set_private_key(key, bd) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_private_key failed")
		}
	}
	if pkey = C.go_openssl_EVP_PKEY_new(); pkey == nil {
		return nil, newOpenSSLError("EVP_PKEY_new failed")
	}
	if C.go_openssl_EVP_PKEY_assign(pkey, C.EVP_PKEY_EC, (unsafe.Pointer)(key)) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_assign failed")
	}
	return pkey, nil
}

func NewPrivateKeyECDSA(curve string, X, Y *big.Int, D *big.Int) (*PrivateKeyECDSA, error) {
	pkey, err := newECKey(curve, X, Y, D)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDSA{_pkey: pkey}
	// Note: Because of the finalizer, any time k.key is passed to cgo,
	// that call must be followed by a call to runtime.KeepAlive(k),
	// to make sure k is not collected (and finalized) before the cgo
	// call returns.
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func SignECDSA(priv *PrivateKeyECDSA, hash []byte) (r, s *big.Int, err error) {
	// We could use ECDSA_do_sign instead but would need to convert
	// the resulting BIGNUMs to *big.Int form. If we're going to do a
	// conversion, converting the ASN.1 form is more convenient and
	// likely not much more expensive.
	sig, err := SignMarshalECDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return nil, nil, err
	}
	return esig.R, esig.S, nil
}

func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte) ([]byte, error) {
	return evpSign(priv.withKey, 0, 0, 0, hash)
}

func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, r, s *big.Int) bool {
	// We could use ECDSA_do_verify instead but would need to convert
	// r and s to BIGNUM form. If we're going to do a conversion, marshaling
	// to ASN.1 is more convenient and likely not much more expensive.
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return false
	}
	return evpVerify(pub.withKey, 0, 0, 0, sig, hash) == nil
}

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
	pkey, err := generateEVPPKey(C.EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, nil, err
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	key := C.go_openssl_EVP_PKEY_get1_EC_KEY(pkey)
	if key == nil {
		return nil, nil, nil, newOpenSSLError("EVP_PKEY_get1_EC_KEY failed")
	}
	defer C.go_openssl_EC_KEY_free(key)
	group := C.go_openssl_EC_KEY_get0_group(key)
	pt := C.go_openssl_EC_KEY_get0_public_key(key)
	bd := C.go_openssl_EC_KEY_get0_private_key(key)
	if pt == nil || bd == nil {
		return nil, nil, nil, newOpenSSLError("EC_KEY_get0_private_key failed")
	}
	bx := C.go_openssl_BN_new()
	if bx == nil {
		return nil, nil, nil, newOpenSSLError("BN_new failed")
	}
	defer C.go_openssl_BN_free(bx)
	by := C.go_openssl_BN_new()
	if by == nil {
		return nil, nil, nil, newOpenSSLError("BN_new failed")
	}
	defer C.go_openssl_BN_free(by)
	if C.go_openssl_EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil) == 0 {
		return nil, nil, nil, newOpenSSLError("EC_POINT_get_affine_coordinates_GFp failed")
	}
	return bnToBig(bx), bnToBig(by), bnToBig(bd), nil
}
