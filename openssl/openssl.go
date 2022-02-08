// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the constant Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package openssl

// #include "goopenssl.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"errors"
	"math/big"
	"runtime"
	"strings"
)

var (
	providerNameFips = C.CString("fips")
	propFipsYes      = C.CString("fips=yes")
	propFipsNo       = C.CString("fips=no")
)

// Init loads and initializes OpenSSL.
// It must be called before any other OpenSSL call.
func Init() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if C.go_openssl_load() == C.NULL {
		return errors.New("openssl: OpenSSL dlopen failed")
	}

	if C.go_openssl_setup() != 1 {
		return errors.New("openssl: OpenSSL setup failed")
	}
	return nil
}

// FIPS returns true if OpenSSL is running in FIPS mode, else returns false.
func FIPS() bool {
	// FIPS_mode is only defined in OpenSSL 1.
	if C._g_FIPS_mode != nil {
		return C.go_openssl_FIPS_mode() == 1
	}
	if C.go_openssl_EVP_default_properties_is_fips_enabled(nil) == 0 {
		return false
	}
	// EVP_default_properties_is_fips_enabled can return true even if the FIPS provider isn't loaded,
	// it is only based on the default properties.
	return C.go_openssl_OSSL_PROVIDER_available(nil, providerNameFips) == 1
}

// SetFIPS enables or disables FIPS mode.
func SetFIPS(enabled bool) error {
	// FIPS_mode_set is only defined in OpenSSL 1.
	if C._g_FIPS_mode_set != nil {
		var mode C.int
		if enabled {
			mode = C.int(1)
		} else {
			mode = C.int(0)
		}
		if C.go_openssl_FIPS_mode_set(mode) != 1 {
			return newOpenSSLError("openssl: FIPS_mode_set")
		}
		return nil
	}
	if enabled {
		if C.go_openssl_OSSL_PROVIDER_available(nil, providerNameFips) == 0 {
			// The last parameter is set to 1 in order to allow loading fallback providers.
			if C.go_openssl_OSSL_PROVIDER_try_load(nil, providerNameFips, 1) == nil {
				return newOpenSSLError("openssl: OSSL_PROVIDER_try_load")
			}
		}
	}

	var prop *C.char
	if enabled {
		prop = propFipsYes
	} else {
		prop = propFipsNo
	}
	if C.go_openssl_EVP_set_default_properties(nil, prop) != 1 {
		return newOpenSSLError("openssl: EVP_set_default_properties")
	}
	return nil
}

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return C.GoString(C.go_openssl_OpenSSL_version(0))
}

func newOpenSSLError(msg string) error {
	var b strings.Builder
	var e C.ulong

	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):\n")

	for {
		e = C.go_openssl_ERR_get_error()
		if e == 0 {
			break
		}
		var buf [256]byte
		C.go_openssl_ERR_error_string_n(e, base(buf[:]), 256)
		b.Write(buf[:])
		b.WriteByte('\n')
	}
	return errors.New(b.String())
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

func bigToBN(x *big.Int) *C.BIGNUM {
	raw := x.Bytes()
	return C.go_openssl_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
}

func bnToBig(bn *C.BIGNUM) *big.Int {
	raw := make([]byte, (C.go_openssl_BN_num_bits(bn)+7)/8)
	n := C.go_openssl_BN_bn2bin(bn, base(raw))
	return new(big.Int).SetBytes(raw[:n])
}

func bigToBn(bnp **C.BIGNUM, b *big.Int) bool {
	if *bnp != nil {
		C.go_openssl_BN_free(*bnp)
		*bnp = nil
	}
	if b == nil {
		return true
	}
	raw := b.Bytes()
	bn := C.go_openssl_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
	if bn == nil {
		return false
	}
	*bnp = bn
	return true
}
