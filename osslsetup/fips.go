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
	// Provider names
	_ProviderNameFips cString = "fips\x00"

	// Digest Names
	_DigestNameSHA2_256 cString = "SHA2-256\x00"
)

// FIPS returns true if OpenSSL is running in FIPS mode and there is
// a provider available that supports FIPS. It returns false otherwise.
// All OpenSSL functions used in here should be tagged with "init_1" or "init_3" in shims.h.
func FIPS() bool {
	switch vMajor {
	case 1:
		return ossl.FIPS_mode() == 1
	case 3, 4:
		// Check if the default properties contain `fips=1`.
		if ossl.EVP_default_properties_is_fips_enabled(nil) != 1 {
			// Note that it is still possible that the provider used by default is FIPS-compliant,
			// but that wouldn't be a system or user requirement.
			return false
		}
		// Check if the SHA-256 algorithm is available. If it is, then we can be sure that there is a provider available that matches
		// the `fips=1` query. Most notably, this works for the common case of using the built-in FIPS provider.
		//
		// Note that this approach has a small chance of false negative if the FIPS provider doesn't provide the SHA-256 algorithm,
		// but that is highly unlikely because SHA-256 is one of the most common algorithms and fundamental to many cryptographic operations.
		// It also has a small chance of false positive if the FIPS provider implements the SHA-256 algorithm but not the other algorithms
		// used by the caller application, but that is also unlikely because the FIPS provider should provide all common algorithms.
		return proveSHA256("")
	default:
		panic(errUnsupportedVersion())
	}
}

// FIPSCapable returns true if the provider used by default matches the `fips=yes` query.
// It is useful for checking whether OpenSSL is capable of running in FIPS mode regardless
// of whether FIPS mode is explicitly enabled. For example, Azure Linux 3 doesn't set the
// `fips=yes` query in the default properties, but sets the default provider to be SCOSSL,
// which is FIPS-capable.
//
// Considerations:
//   - Multiple calls to FIPSCapable can return different values if [SetFIPS] is called in between.
//   - Can return true even if [FIPS] returns false, because [FIPS] also checks whether
//     the default properties contain `fips=yes`.
//   - When using OpenSSL 3, will always return true if [FIPS] returns true.
//   - When using OpenSSL 1, will always return the same value as [FIPS].
//   - OpenSSL 3 doesn't provide a way to know if a provider is FIPS-capable. This function uses
//     some heuristics that should be treated as an implementation detail that may change in the future.
func FIPSCapable() bool {
	if FIPS() {
		return true
	}
	switch vMajor {
	case 3, 4:
		// Load the provider with and without the `fips=yes` query.
		// If the providers are the same, then the default provider is FIPS-capable.
		provFIPS := sha256Provider(_ProviderNameFips)
		if provFIPS == nil {
			return false
		}
		provDefault := sha256Provider("")
		return provFIPS == provDefault
	}
	return false
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

// proveSHA256 checks if the SHA-256 algorithm is available
// using the given properties.
func proveSHA256(props cString) bool {
	return sha256Provider(props) != nil
}
