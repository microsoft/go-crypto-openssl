// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a mirror of crypto/internal/boring/bbig/big.go.

package bbig

import (
	"encoding/asn1"
	"math/big"
	"unsafe"

	"github.com/microsoft/go-crypto-openssl/openssl"
)

func Enc(b *big.Int) openssl.BigInt {
	if b == nil {
		return nil
	}
	x := b.Bits()
	if len(x) == 0 {
		return openssl.BigInt{}
	}
	// TODO: Use unsafe.Slice((*uint)(&x[0]), len(x)) once go1.16 is no longer supported.
	return (*[1 << 30]uint)(unsafe.Pointer(&x[0]))[:len(x)]
}

func Dec(b openssl.BigInt) *big.Int {
	if b == nil {
		return nil
	}
	if len(b) == 0 {
		return new(big.Int)
	}
	// TODO: Use unsafe.Slice((*uint)(&b[0]), len(b)) once go1.16 is no longer supported.
	x := (*[1 << 30]big.Word)(unsafe.Pointer(&b[0]))[:len(b)]
	return new(big.Int).SetBits(x)
}

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
	x, y, d, err := openssl.GenerateKeyECDSA(curve)
	if err != nil {
		return nil, nil, nil, err
	}
	return Dec(x), Dec(y), Dec(d), nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func SignECDSA(priv *openssl.PrivateKeyECDSA, hash []byte) (r, s *big.Int, err error) {
	sig, err := openssl.SignMarshalECDSA(priv, hash)
	if err != nil {
		return nil, nil, err
	}
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return nil, nil, err
	}
	return esig.R, esig.S, nil
}

func NewPrivateKeyECDSA(curve string, X, Y, D *big.Int) (*openssl.PrivateKeyECDSA, error) {
	return openssl.NewPrivateKeyECDSA(curve, Enc(X), Enc(Y), Enc(D))
}

func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*openssl.PublicKeyECDSA, error) {
	return openssl.NewPublicKeyECDSA(curve, Enc(X), Enc(Y))
}

func VerifyECDSA(pub *openssl.PublicKeyECDSA, hash []byte, r, s *big.Int) bool {
	// We could use ECDSA_do_verify instead but would need to convert
	// r and s to BIGNUM form. If we're going to do a conversion, marshaling
	// to ASN.1 is more convenient and likely not much more expensive.
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return false
	}
	return openssl.VerifyECDSA(pub, hash, sig)
}

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv *big.Int, err error) {
	bN, bE, bD, bP, bQ, bDp, bDq, bQinv, err1 := openssl.GenerateKeyRSA(bits)
	if err1 != nil {
		err = err1
		return
	}
	N = Dec(bN)
	E = Dec(bE)
	D = Dec(bD)
	P = Dec(bP)
	Q = Dec(bQ)
	Dp = Dec(bDp)
	Dq = Dec(bDq)
	Qinv = Dec(bQinv)
	return
}

func NewPublicKeyRSA(N, E *big.Int) (*openssl.PublicKeyRSA, error) {
	return openssl.NewPublicKeyRSA(Enc(N), Enc(E))
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv *big.Int) (*openssl.PrivateKeyRSA, error) {
	return openssl.NewPrivateKeyRSA(Enc(N), Enc(E), Enc(D), Enc(P), Enc(Q), Enc(Dp), Enc(Dq), Enc(Qinv))
}
