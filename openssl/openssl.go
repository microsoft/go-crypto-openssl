// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

// #include "goopenssl.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"errors"
	"math/big"
	"runtime"
	"strconv"
	"strings"
)

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")
	propFipsYes         = C.CString("fips=yes")
	propFipsNo          = C.CString("fips=no")
	algProve            = C.CString("SHA2-256")
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

// providerAvailable looks through provider's digests
// checking if there is any that matches the pprog query.
func providerAvailable(pprog *C.char) bool {
	C.go_openssl_ERR_set_mark()
	md := C.go_openssl_EVP_MD_fetch(nil, algProve, pprog)
	C.go_openssl_ERR_pop_to_mark()
	if md == nil {
		return false
	}
	C.go_openssl_EVP_MD_free(md)
	return true
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
	return providerAvailable(propFipsYes)
}

// SetFIPS enables or disables FIPS mode.
//
// It implements the following provider fallback logic for OpenSSL 3:
//    - The "fips" provider is loaded if enabled=true and no loaded provider matches "fips=yes".
//    - The "default" provider is loaded if enabled=false and no loaded provider matches "fips=no".
// This logic allows advanced users to define their own providers that match "fips=yes" and "fips=no" using the OpenSSL config file.
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
	var pprop, provName *C.char
	if enabled {
		pprop = propFipsYes
		provName = providerNameFips
	} else {
		pprop = propFipsNo
		provName = providerNameDefault
	}
	// Check if there is any provided that matches pprop.
	if !providerAvailable(pprop) {
		// If not, fallback to provName provider.
		if C.go_openssl_OSSL_PROVIDER_load(nil, provName) == nil {
			return newOpenSSLError("openssl: OSSL_PROVIDER_try_load")
		}
		// Make sure we now have a provider available.
		if !providerAvailable(pprop) {
			return fail("SetFIPS(" + strconv.FormatBool(enabled) + ") not supported")
		}
	}
	if C.go_openssl_EVP_set_default_properties(nil, pprop) != 1 {
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
