// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

// #include "goopenssl.h"
// #include <dlfcn.h>
// #cgo LDFLAGS: -ldl
import "C"
import (
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")
	propFipsYes         = C.CString("fips=yes")
	propFipsNo          = C.CString("fips=no")
	algProve            = C.CString("SHA2-256")
)

var (
	initOnce sync.Once
	// errInit is set when first calling Init().
	errInit error
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor int
)

// knownVersions is a list of supported and well-known libcrypto.so suffixes in decreasing version order.
//
// FreeBSD library version numbering does not directly align to the version of OpenSSL.
// Its preferred search order is 11 -> 111.
//
// Some distributions use 1.0.0 and others (such as Debian) 1.0.2 to refer to the same OpenSSL 1.0.2 version.
//
// Fedora derived distros use different naming for the version 1.0.x.
var knownVersions = [...]string{"3", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}

func errUnsuportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + strconv.Itoa(vMajor) + "." + strconv.Itoa(vMinor))
}

// Init loads and initializes OpenSSL.
// It must be called before any other OpenSSL call.
//
// Only the first call to Init is effective,
// subsequent calls will return the same error result as the one from the first call.
//
// If GO_OPENSSL_VERSION_OVERRIDE environment variable is not empty, its value will be appended to the OpenSSL shared library name
// as a version suffix when calling dlopen. For example, "GO_OPENSSL_VERSION_OVERRIDE=1.1.1k-fips"
// makes Init look for the shared library libcrypto.so.1.1.1k-fips.
// If GO_OPENSSL_VERSION_OVERRIDE environment variable is empty, Init will try to load the OpenSSL shared library
// using a list if supported and well-known version suffixes, going from higher to lower versions.
func Init() error {
	initOnce.Do(func() {
		version, _ := syscall.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
		handle, err := loadLibrary(version)
		if err != nil {
			errInit = err
			return
		}

		vMajor = int(C.go_openssl_version_major(handle))
		vMinor = int(C.go_openssl_version_minor(handle))
		if vMajor == -1 || vMinor == -1 {
			errInit = errors.New("openssl: can't retrieve OpenSSL version")
			return
		}
		var supported bool
		if vMajor == 1 {
			supported = vMinor == 0 || vMinor == 1
		} else if vMajor == 3 {
			// OpenSSL team guarantees API and ABI compatibility within the same major version since OpenSSL 3.
			supported = true
		}
		if !supported {
			errInit = errUnsuportedVersion()
			return
		}

		C.go_openssl_load_functions(handle, C.int(vMajor), C.int(vMinor))
		C.go_openssl_OPENSSL_init()
		if vMajor == 1 && vMinor == 0 {
			if C.go_openssl_thread_setup() != 1 {
				errInit = newOpenSSLError("openssl: thread setup")
				return
			}
			C.go_openssl_OPENSSL_add_all_algorithms_conf()
			C.go_openssl_ERR_load_crypto_strings()
		} else {
			flags := C.uint64_t(C.GO_OPENSSL_INIT_ADD_ALL_CIPHERS | C.GO_OPENSSL_INIT_ADD_ALL_DIGESTS | C.GO_OPENSSL_INIT_LOAD_CONFIG | C.GO_OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
			if C.go_openssl_OPENSSL_init_crypto(flags, nil) != 1 {
				errInit = newOpenSSLError("openssl: init crypto")
				return
			}
		}
	})
	return errInit
}

func dlopen(version string) unsafe.Pointer {
	cv := C.CString("libcrypto.so." + version)
	defer C.free(unsafe.Pointer(cv))
	return C.dlopen(cv, C.RTLD_LAZY|C.RTLD_LOCAL)
}

func loadLibrary(version string) (unsafe.Pointer, error) {
	if version != "" {
		// If version is specified try to load it or error out.
		handle := dlopen(version)
		if handle == nil {
			errstr := C.GoString(C.dlerror())
			return nil, errors.New("openssl: can't load libcrypto.so." + version + ": " + errstr)
		}
		return handle, nil
	}
	for _, v := range knownVersions {
		handle := dlopen(v)
		if handle != nil {
			return handle, nil
		}
	}
	return nil, errors.New("openssl: can't load libcrypto.so using any known version suffix")
}

// providerAvailable looks through provider's digests
// checking if there is any that matches the props query.
func providerAvailable(props *C.char) bool {
	C.go_openssl_ERR_set_mark()
	md := C.go_openssl_EVP_MD_fetch(nil, algProve, props)
	C.go_openssl_ERR_pop_to_mark()
	if md == nil {
		return false
	}
	C.go_openssl_EVP_MD_free(md)
	return true
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
		// EVP_default_properties_is_fips_enabled can return true even if the FIPS provider isn't loaded,
		// it is only based on the default properties.
		return providerAvailable(propFipsYes)
	default:
		panic(errUnsuportedVersion())
	}
}

// SetFIPS enables or disables FIPS mode.
//
// It implements the following provider fallback logic for OpenSSL 3:
//    - The "fips" provider is loaded if enabled=true and no loaded provider matches "fips=yes".
//    - The "default" provider is loaded if enabled=false and no loaded provider matches "fips=no".
// This logic allows advanced users to define their own providers that match "fips=yes" and "fips=no" using the OpenSSL config file.
func SetFIPS(enabled bool) error {
	switch vMajor {
	case 1:
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
	case 3:
		var props, provName *C.char
		if enabled {
			props = propFipsYes
			provName = providerNameFips
		} else {
			props = propFipsNo
			provName = providerNameDefault
		}
		// Check if there is any provider that matches props.
		if !providerAvailable(props) {
			// If not, fallback to provName provider.
			if C.go_openssl_OSSL_PROVIDER_load(nil, provName) == nil {
				return newOpenSSLError("openssl: OSSL_PROVIDER_try_load")
			}
			// Make sure we now have a provider available.
			if !providerAvailable(props) {
				return fail("SetFIPS(" + strconv.FormatBool(enabled) + ") not supported")
			}
		}
		if C.go_openssl_EVP_set_default_properties(nil, props) != 1 {
			return newOpenSSLError("openssl: EVP_set_default_properties")
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
	if x == nil {
		return nil
	}
	raw := x.Bytes()
	return C.go_openssl_BN_bin2bn(base(raw), C.size_t(len(raw)), nil)
}

func bnToBig(bn *C.BIGNUM) *big.Int {
	if bn == nil {
		return nil
	}
	raw := make([]byte, (C.go_openssl_BN_num_bits(bn)+7)/8)
	n := C.go_openssl_BN_bn2bin(bn, base(raw))
	return new(big.Int).SetBytes(raw[:n])
}
