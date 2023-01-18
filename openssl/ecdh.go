// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"runtime"
)

type PublicKeyECDH struct {
	_pkey C.GO_EVP_PKEY_PTR
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

type PrivateKeyECDH struct {
	_pkey C.GO_EVP_PKEY_PTR
}

func (k *PrivateKeyECDH) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	key := C.go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name")
	}
	var k *PublicKeyECDH
	defer func() {
		if k == nil {
			C.go_openssl_EC_KEY_free(key)
		}
	}()
	if vMajor == 1 && vMinor == 0 {
		// EC_KEY_oct2key does not exist on OpenSSL 1.0.2,
		// we have to simulate it.
		group := C.go_openssl_EC_KEY_get0_group(key)
		pt := C.go_openssl_EC_POINT_new(group)
		if pt == nil {
			return nil, newOpenSSLError("EC_POINT_new")
		}
		defer C.go_openssl_EC_POINT_free(pt)
		if C.go_openssl_EC_POINT_oct2point(group, pt, base(bytes), C.size_t(len(bytes)), nil) != 1 {
			return nil, errors.New("point not on curve")
		}
		if C.go_openssl_EC_KEY_set_public_key(key, pt) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_public_key")
		}
	} else {
		if C.go_openssl_EC_KEY_oct2key(key, base(bytes), C.size_t(len(bytes)), nil) != 1 {
			return nil, newOpenSSLError("EC_KEY_oct2key")
		}
	}
	pkey, err := newEVPPKEY(key)
	if err != nil {
		return nil, err
	}
	k = &PublicKeyECDH{pkey, append([]byte(nil), bytes...)}
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	b := bytesToBN(bytes)
	if b == nil {
		return nil, newOpenSSLError("BN_bin2bn failed")
	}
	defer C.go_openssl_BN_free(b)
	key := C.go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name")
	}
	var pkey C.GO_EVP_PKEY_PTR
	defer func() {
		if pkey == nil {
			C.go_openssl_EC_KEY_free(key)
		}
	}()
	if C.go_openssl_EC_KEY_set_private_key(key, b) != 1 {
		return nil, newOpenSSLError("EC_KEY_set_private_key")
	}
	pkey, err = newEVPPKEY(key)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDH{pkey}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	key := C.go_openssl_EVP_PKEY_get1_EC_KEY(k._pkey)
	if key == nil {
		return nil, newOpenSSLError("EVP_PKEY_get1_EC_KEY")
	}
	defer C.go_openssl_EC_KEY_free(key)
	group := C.go_openssl_EC_KEY_get0_group(key)
	if group == nil {
		return nil, newOpenSSLError("EC_KEY_get0_group")
	}
	pt := C.go_openssl_EC_KEY_get0_public_key(key)
	if pt == nil {
		// The public key will be nil if k has been generated using
		// NewPrivateKeyECDH instead of GenerateKeyECDH.
		//
		// OpenSSL does not expose any method to generate the public
		// key from the private key [1], so we have to calculate it here
		// https://github.com/openssl/openssl/issues/18437#issuecomment-1144717206
		pt = C.go_openssl_EC_POINT_new(group)
		if pt == nil {
			return nil, newOpenSSLError("EC_POINT_new")
		}
		defer C.go_openssl_EC_POINT_free(pt)
		kbig := C.go_openssl_EC_KEY_get0_private_key(key)
		if C.go_openssl_EC_POINT_mul(group, pt, kbig, nil, nil, nil) == 0 {
			return nil, newOpenSSLError("EC_POINT_mul")
		}
	}
	n := C.go_openssl_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, nil, 0, nil)
	if n == 0 {
		return nil, newOpenSSLError("EC_POINT_point2oct")
	}
	bytes := make([]byte, n)
	n = C.go_openssl_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, base(bytes), C.size_t(len(bytes)), nil)
	if int(n) != len(bytes) {
		return nil, newOpenSSLError("EC_POINT_point2oct")
	}
	pub := &PublicKeyECDH{k._pkey, bytes}
	// Note: Same as in NewPublicKeyECDH regarding finalizer and KeepAlive.
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)
	ctx := C.go_openssl_EVP_PKEY_CTX_new(priv._pkey, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new")
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if C.go_openssl_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	if C.go_openssl_EVP_PKEY_derive_set_peer(ctx, pub._pkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_set_peer")
	}
	var outLen C.size_t
	if C.go_openssl_EVP_PKEY_derive(ctx, nil, &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	out := make([]byte, outLen)
	if C.go_openssl_EVP_PKEY_derive(ctx, base(out), &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	return out, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	pkey, err := generateEVPPKey(C.GO_EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, err
	}
	var k *PrivateKeyECDH
	defer func() {
		if k == nil {
			C.go_openssl_EVP_PKEY_free(pkey)
		}
	}()
	key := C.go_openssl_EVP_PKEY_get1_EC_KEY(pkey)
	if key == nil {
		return nil, nil, newOpenSSLError("EVP_PKEY_get1_EC_KEY")
	}
	defer C.go_openssl_EC_KEY_free(key)
	b := C.go_openssl_EC_KEY_get0_private_key(key)
	if b == nil {
		return nil, nil, newOpenSSLError("EC_KEY_get0_private_key")
	}
	bits := C.go_openssl_EVP_PKEY_get_bits(pkey)
	out := make([]byte, (bits+7)/8)
	if C.go_openssl_BN_bn2binpad(b, base(out), C.int(len(out))) == 0 {
		return nil, nil, newOpenSSLError("BN_bn2binpad")
	}
	k = &PrivateKeyECDH{pkey}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, out, nil
}
