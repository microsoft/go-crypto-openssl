// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// These wrappers only exist for code reuse in places where we need the old pre-go1.19 signature.

package bridge

import (
	"encoding/asn1"
	"math/big"

	"github.com/microsoft/go-crypto-openssl/openssl"
	"github.com/microsoft/go-crypto-openssl/openssl/bbig"
)

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
	x, y, d, err := openssl.GenerateKeyECDSA(curve)
	if err != nil {
		return nil, nil, nil, err
	}
	return bbig.Dec(x), bbig.Dec(y), bbig.Dec(d), nil
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
	return openssl.NewPrivateKeyECDSA(curve, bbig.Enc(X), bbig.Enc(Y), bbig.Enc(D))
}

func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*openssl.PublicKeyECDSA, error) {
	return openssl.NewPublicKeyECDSA(curve, bbig.Enc(X), bbig.Enc(Y))
}

func VerifyECDSA(pub *openssl.PublicKeyECDSA, hash []byte, r, s *big.Int) bool {
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
	N = bbig.Dec(bN)
	E = bbig.Dec(bE)
	D = bbig.Dec(bD)
	P = bbig.Dec(bP)
	Q = bbig.Dec(bQ)
	Dp = bbig.Dec(bDp)
	Dq = bbig.Dec(bDq)
	Qinv = bbig.Dec(bQinv)
	return
}

func NewPublicKeyRSA(N, E *big.Int) (*openssl.PublicKeyRSA, error) {
	return openssl.NewPublicKeyRSA(bbig.Enc(N), bbig.Enc(E))
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv *big.Int) (*openssl.PrivateKeyRSA, error) {
	return openssl.NewPrivateKeyRSA(
		bbig.Enc(N), bbig.Enc(E), bbig.Enc(D),
		bbig.Enc(P), bbig.Enc(Q),
		bbig.Enc(Dp), bbig.Enc(Dq), bbig.Enc(Qinv),
	)
}
