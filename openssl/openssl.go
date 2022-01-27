// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the constant Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package openssl

// #include "goopenssl.h"
// #include <dlfcn.h>
// #cgo LDFLAGS: -ldl
import "C"
import (
	"errors"
	"math/big"
	"runtime"
	"strings"
	"unsafe"
)

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")

	sentinelNameV1_0 = C.CString("EVP_MD_CTX_cleanup")
	sentinelNameV1   = C.CString("FIPS_mode")
)

// Init loads and initializes OpenSSL.
// It must be called before any other OpenSSL call.
//
// If version is not empty it will be appended to the OpenSSL shared library name as a version suffix when calling dlopen.
// For example, "version=1.1.1k-fips" makes Init look for the shared library libcrypto.so.1.1.1k-fips.
//
// If version is empty Init will try to load the OpenSSL shared library using a list if supported and well-known version suffixes,
// going from higher to lower versions.
func Init(version string) error {
	handle, err := loadLibrary(version)
	if err != nil {
		return err
	}
	// v1_0_sentinel is only defined up to OpenSSL 1.0.x.
	v1_0_sentinel := C.dlsym(handle, sentinelNameV1_0)
	// v1_sentinel is only defined up to OpenSSL 1.x.
	v1_sentinel := C.dlsym(handle, sentinelNameV1)

	C.go_openssl_load_functions(handle, v1_0_sentinel, v1_sentinel)

	if v1_0_sentinel != nil {
		return initV1_0()
	}
	if v1_sentinel != nil {
		return initV1_1()
	}
	return initV3()
}

// FIPS returns true if OpenSSL is running in FIPS mode, else returns false.
func FIPS() bool {
	return C.go_openssl_FIPS_Enabled() == 1
}

// SetFIPS enables or disables FIPS mode.
func SetFIPS(enabled bool) error {
	var mode C.int
	if enabled {
		mode = C.int(1)
	} else {
		mode = C.int(0)
	}
	if C.go_openssl_FIPS_Enable(mode) != 1 {
		return newOpenSSLError("openssl: set FIPS mode")
	}
	return nil
}

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return C.GoString(C.go_openssl_OpenSSL_version(0))
}

func initV1_0() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	C.go_openssl_OPENSSL_init()
	if C.go_openssl_thread_setup() != 1 {
		return newOpenSSLError("openssl: thread setup")
	}
	C.go_openssl_OPENSSL_add_all_algorithms_conf()
	C.go_openssl_ERR_load_crypto_strings()
	return nil
}

func initV1_1() error {
	C.go_openssl_OPENSSL_init()
	flags := C.uint64_t(C.OPENSSL_INIT_ADD_ALL_CIPHERS | C.OPENSSL_INIT_ADD_ALL_DIGESTS | C.OPENSSL_INIT_LOAD_CONFIG | C.OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
	if C.go_openssl_OPENSSL_init_crypto(flags, nil) != 1 {
		return newOpenSSLError("openssl: init crypto")
	}
	return nil
}

func initV3() error {
	err := initV1_1()
	if err != nil {
		return err
	}
	// Load the default provider in case FIPS provider is not used.
	if C.go_openssl_OSSL_PROVIDER_load(nil, providerNameDefault) == nil {
		return newOpenSSLError("openssl: load default provider")
	}
	// Try to load the FIPS provider in case it is enabled later on.
	// The last parameter is set to 1 in order to allow
	// loading fallback providers.
	// The error can be skipped as we still don't know if it is required,
	// and if so we will use OSSL_PROVIDER_available(NULL, "fips") when necessary.
	C.go_openssl_OSSL_PROVIDER_try_load(nil, providerNameFips, 1)
	return nil
}

func dlopen(version string) unsafe.Pointer {
	cv := C.CString("libcrypto.so." + version)
	defer C.free(unsafe.Pointer(cv))
	return C.dlopen(cv, C.RTLD_LAZY|C.RTLD_GLOBAL)
}

// knownVersions is a list of supported and well-known libcrypto.so suffixes in decreasing version order.
//
// FreeBSD library version numbering does not directly align to the version of OpenSSL.
// Its preferred search order is 11 -> 111.
//
// Some distributions use 1.0.0 and others (such as Debian) 1.0.2 to refer to the same OpenSSL 1.0.2 version.
//
// Fedora derived distros use different naming for the version 1.0.x.
var knownVersions = [...]string{"3", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}

func loadLibrary(version string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	if version != "" {
		// If version is specified try to load it or error out.
		handle = dlopen(version)
		if handle == nil {
			errstr := C.GoString(C.dlerror())
			return nil, errors.New("openssl: can't load libcrypto.so." + version + " : " + errstr)
		}
		return handle, nil
	}
	for _, v := range knownVersions {
		handle = dlopen(v)
		if handle != nil {
			return handle, nil
		}
	}
	return nil, errors.New("openssl: can't load libcrypto.so using any known version suffix")
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
