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
	"strconv"
	"strings"
	"unsafe"
)

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")

	sentinelNameV1_0 = C.CString("EVP_MD_CTX_cleanup")
	sentinelNameV1   = C.CString("FIPS_mode")
)

func errUnsuportedVersion() error {
	return errors.New("openssl: OpenSSL major version: " + strconv.Itoa(vMajor))
}

// vMajor and vMinor hold the major/minor OpenSSL version.
// It is only populated if Init has been called.
var vMajor, vMinor int

// Init loads and initializes OpenSSL.
// It must be called before any other OpenSSL call.
//
// If GO_OPENSSL_VERSION_OVERRIDE enviornment variable is not empty, its value will be appended to the OpenSSL shared library name
// as a version suffix when calling dlopen. For example, "GO_OPENSSL_VERSION_OVERRIDE=1.1.1k-fips"
// makes Init look for the shared library libcrypto.so.1.1.1k-fips.
// If GO_OPENSSL_VERSION_OVERRIDE enviornment variable is empty, Init will try to load the OpenSSL shared library
// using a list if supported and well-known version suffixes, going from higher to lower versions.
func Init() error {
	// version, _ := syscall.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	handle, err := loadLibrary("3.0.1")
	if err != nil {
		return err
	}
	// v1_0_sentinel is only defined up to OpenSSL 1.0.x.
	v1_0_sentinel := C.dlsym(handle, sentinelNameV1_0)
	// v1_sentinel is only defined up to OpenSSL 1.x.
	v1_sentinel := C.dlsym(handle, sentinelNameV1)

	C.go_openssl_load_functions(handle, v1_0_sentinel, v1_sentinel)

	if v1_sentinel != nil {
		vMajor = 1
		if v1_0_sentinel != nil {
			vMinor = 0
			return initV1_0()
		}
		vMinor = 1
		return initV1_1()
	}
	vMajor = 3
	vMinor = 0
	return initV3()
}

// FIPS returns true if OpenSSL is running in FIPS mode, else returns false.
func FIPS() bool {
	switch vMajor {
	case 1:
		return C.go_openssl_FIPS_mode() == 1
	case 3:
		if C.go_openssl_EVP_default_properties_is_fips_enabled(nil) == 0 {
			return false
		}
		return C.go_openssl_OSSL_PROVIDER_available(nil, providerNameFips) == 1
	default:
		panic(errUnsuportedVersion())
	}
}

// SetFIPS enables or disables FIPS mode.
func SetFIPS(enabled bool) error {
	var mode C.int
	if enabled {
		mode = C.int(1)
	} else {
		mode = C.int(0)
	}
	switch vMajor {
	case 1:
		if C.go_openssl_FIPS_mode_set(mode) != 1 {
			return newOpenSSLError("openssl: FIPS_mode_set")
		}
		return nil
	case 3:
		if C.go_openssl_OSSL_PROVIDER_available(nil, providerNameFips) == 0 {
			return fail("fips provider not available")
		}
		if C.go_openssl_EVP_default_properties_enable_fips(nil, mode) != 1 {
			return newOpenSSLError("openssl: EVP_default_properties_enable_fips")
		}
		return nil
	default:
		panic(errUnsuportedVersion())
	}
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
	// The last parameter is set to 1 in order to allow loading fallback providers.
	if C.go_openssl_OSSL_PROVIDER_try_load(nil, providerNameFips, 1) == nil {
		// The error can be skipped as we still don't know if FIPS is required.
		// If it is we will use OSSL_PROVIDER_available(NULL, "fips") to check if the FIPS provider is available.
		for {
			if C.go_openssl_ERR_get_error() == 0 {
				break
			}
		}
	}
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
