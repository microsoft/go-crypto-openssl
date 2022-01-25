// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"bytes"
	"crypto"
	"testing"
)

func TestRSAKeyGeneration(t *testing.T) {
	for _, size := range []int{128, 1024, 2048, 3072} {
		priv, pub := newRSAKey(t, size)
		testRSAKeyBasics(t, priv, pub)
	}
}

func testRSAKeyBasics(t *testing.T, priv *PrivateKeyRSA, pub *PublicKeyRSA) {
	// Cannot call encrypt/decrypt directly. Test via PKCS1v15.
	msg := []byte("hi!")
	enc, err := EncryptRSAPKCS1(pub, msg)
	if err != nil {
		t.Errorf("EncryptPKCS1v15: %v", err)
		return
	}
	dec, err := DecryptRSAPKCS1(priv, enc)
	if err != nil {
		t.Errorf("DecryptPKCS1v15: %v", err)
		return
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
}

func TestEncryptDecryptOAEP(t *testing.T) {
	sha256 := NewSHA256()
	msg := []byte("hi!")
	label := []byte("ho!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := EncryptRSAOAEP(sha256, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptRSAOAEP(sha256, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
}

func TestEncryptDecryptOAEP_WrongLabel(t *testing.T) {
	sha256 := NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := EncryptRSAOAEP(sha256, pub, msg, []byte("ho!"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptRSAOAEP(sha256, priv, enc, []byte("wrong!"))
	if err == nil {
		t.Errorf("error expected")
	}
	if dec != nil {
		t.Errorf("got:%x want: nil", dec)
	}
}

func TestSignVerifyPKCS1v15(t *testing.T) {
	sha256 := NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	hashed := sha256.Sum(msg)
	signed, err := SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyRSAPKCS1v15(pub, crypto.SHA256, hashed, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyPKCS1v15_Unhashed(t *testing.T) {
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	signed, err := SignRSAPKCS1v15(priv, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyRSAPKCS1v15(pub, 0, msg, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyPKCS1v15_Invalid(t *testing.T) {
	sha256 := NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	hashed := sha256.Sum(msg)
	signed, err := SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyRSAPKCS1v15(pub, crypto.SHA256, msg, signed)
	if err == nil {
		t.Fatal("error expected")
	}
}

func TestSignVerifyRSAPSS(t *testing.T) {
	sha1 := NewSHA1()
	priv, pub := newRSAKey(t, 2048)
	sha1.Sum([]byte("testing"))
	hashed := sha1.Sum(nil)
	signed, err := SignRSAPSS(priv, crypto.SHA1, hashed, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyRSAPSS(pub, crypto.SHA1, hashed, signed, 0)
	if err != nil {
		t.Fatal(err)
	}
}

func newRSAKey(t *testing.T, size int) (*PrivateKeyRSA, *PublicKeyRSA) {
	t.Helper()
	N, E, D, P, Q, Dp, Dq, Qinv, err := GenerateKeyRSA(size)
	if err != nil {
		t.Errorf("GenerateKeyRSA(%d): %v", size, err)
	}
	priv, err := NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		t.Errorf("NewPrivateKeyRSA(%d): %v", size, err)
	}
	pub, err := NewPublicKeyRSA(N, E)
	if err != nil {
		t.Errorf("NewPublicKeyRSA(%d): %v", size, err)
	}
	return priv, pub
}
