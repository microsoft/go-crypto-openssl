// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P224", elliptic.P224()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestECDSAKeyGeneration(t *testing.T) {
	testAllCurves(t, testECDSAKeyGeneration)
}

func testECDSAKeyGeneration(t *testing.T, c elliptic.Curve) {
	priv, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func TestECDSASignAndVerify(t *testing.T) {
	testAllCurves(t, testECDSASignAndVerify)
}

func testECDSASignAndVerify(t *testing.T, c elliptic.Curve) {
	key, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := NewPrivateKeyECDSA(key.Params().Name, key.X, key.Y, key.D)
	if err != nil {
		t.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := SignECDSA(priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	pub, err := NewPublicKeyECDSA(key.Params().Name, key.X, key.Y)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyECDSA(pub, hashed, r, s) {
		t.Errorf("Verify failed")
	}
	hashed[0] ^= 0xff
	if VerifyECDSA(pub, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func generateKeycurve(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	x, y, d, err := GenerateKeyECDSA(c.Params().Name)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}, nil
}
