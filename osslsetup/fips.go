// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cmd_go_bootstrap

package osslsetup

import (
	"unsafe"

	"github.com/microsoft/go-crypto-openssl/internal/ossl"
)

// cString is a null-terminated string,
// akin to C's char*.
type cString string

// ptr returns a pointer to the string data.
// It panics if the string is not null-terminated.
//
// The memory pointed to by the returned pointer should
// not be modified and it must only be passed to
// "const char*" parameters. Any attempt to modify it
// will result in a runtime panic, as Go strings are
// allocated in read-only memory.
func (s cString) ptr() *byte {
	if len(s) == 0 {
		return nil
	}
	if s[len(s)-1] != 0 {
		panic("must be null-terminated")
	}
	return unsafe.StringData(string(s))
}

const (
	_ProviderNameFips   cString = "fips\x00"
	_DigestNameSHA2_256 cString = "SHA2-256\x00"
)

// FIPS returns true if the provider used by default matches the `fips=yes` query.
// It is useful for checking whether OpenSSL is capable of running in FIPS mode regardless
// of whether the `fips=yes` query is explicitly enabled. For example, Azure Linux 3 doesn't set the
// `fips=yes` query in the default properties, but sets the default provider to be SCOSSL,
// which is FIPS-capable.
func FIPS() bool {
	switch vMajor {
	case 1:
		return ossl.FIPS_mode() == 1
	default:
		// Load the provider with and without the `fips=yes` query.
		// If the providers are the same, then the default provider is FIPS-capable.
		provFIPS := sha256Provider(_ProviderNameFips)
		if provFIPS == nil {
			return false
		}
		provDefault := sha256Provider("")
		return provFIPS == provDefault
	}
}

// sha256Provider returns the provider for the SHA-256 algorithm
// using the given properties.
func sha256Provider(props cString) ossl.OSSL_PROVIDER_PTR {
	md, _ := ossl.EVP_MD_fetch(nil, _DigestNameSHA2_256.ptr(), props.ptr())
	if md == nil {
		return nil
	}
	defer ossl.EVP_MD_free(md)
	return ossl.EVP_MD_get0_provider(md)
}
