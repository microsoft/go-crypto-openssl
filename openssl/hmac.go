// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"hash"
	"runtime"
	"unsafe"
)

var (
	paramAlgHMAC = C.CString("HMAC")
	paramDigest  = C.CString("digest")
)

// NewHMAC returns a new HMAC using OpenSSL.
// The function h must return a hash implemented by
// OpenSSL (for example, h could be openssl.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil
	}

	var hkey []byte
	if len(key) > 0 {
		// Note: Could hash down long keys here using EVP_Digest.
		hkey = make([]byte, len(key))
		copy(hkey, key)
	} else {
		// This is supported in OpenSSL/Standard lib and as such
		// we must support it here. When using HMAC with a null key
		// HMAC_Init will try and reuse the key from the ctx. This is
		// not the bahavior previously implemented, so as a workaround
		// we pass an "empty" key.
		hkey = make([]byte, C.GO_EVP_MAX_MD_SIZE)
	}
	switch vMajor {
	case 1:
		return newHMAC1(hkey, ch, md)
	case 3:
		return newHMAC3(hkey, ch, md)
	default:
		panic(errUnsuportedVersion())
	}
}

// hmac1 implements hash.Hash
// using functions available in OpenSSL 1.
type hmac1 struct {
	md        C.GO_EVP_MD_PTR
	ctx       C.GO_HMAC_CTX_PTR
	size      int
	blockSize int
	key       []byte
	sum       []byte
}

func newHMAC1(key []byte, h hash.Hash, md C.GO_EVP_MD_PTR) *hmac1 {
	hmac := &hmac1{
		md:        md,
		size:      h.Size(),
		blockSize: h.BlockSize(),
		key:       key,
		ctx:       hmac1CtxNew(),
	}
	runtime.SetFinalizer(hmac, (*hmac1).finalize)
	hmac.Reset()
	return hmac
}

func (h *hmac1) Reset() {
	hmac1CtxReset(h.ctx)

	if C.go_openssl_HMAC_Init_ex(h.ctx, unsafe.Pointer(&h.key[0]), C.int(len(h.key)), h.md, nil) == 0 {
		panic("openssl: HMAC_Init failed")
	}
	if size := C.go_openssl_EVP_MD_get_size(h.md); size != C.int(h.size) {
		println("openssl: HMAC size:", size, "!=", h.size)
		panic("openssl: HMAC size mismatch")
	}
	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *hmac1) finalize() {
	hmac1CtxFree(h.ctx)
}

func (h *hmac1) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.go_openssl_HMAC_Update(h.ctx, base(p), C.size_t(len(p)))
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *hmac1) Size() int {
	return h.size
}

func (h *hmac1) BlockSize() int {
	return h.blockSize
}

func (h *hmac1) Sum(in []byte) []byte {
	if h.sum == nil {
		size := h.Size()
		h.sum = make([]byte, size)
	}
	// Make copy of context because Go hash.Hash mandates
	// that Sum has no effect on the underlying stream.
	// In particular it is OK to Sum, then Write more, then Sum again,
	// and the second Sum acts as if the first didn't happen.
	ctx2 := hmac1CtxNew()
	defer hmac1CtxFree(ctx2)
	if C.go_openssl_HMAC_CTX_copy(ctx2, h.ctx) == 0 {
		panic("openssl: HMAC_CTX_copy failed")
	}
	C.go_openssl_HMAC_Final(ctx2, base(h.sum), nil)
	return append(in, h.sum...)
}

func hmac1CtxNew() C.GO_HMAC_CTX_PTR {
	if vMajor == 1 && vMinor == 0 {
		// 0x120 is the sizeof value when building against OpenSSL 1.0.2 on Ubuntu 16.04.
		ctx := (C.GO_HMAC_CTX_PTR)(C.malloc(0x120))
		if ctx != nil {
			C.go_openssl_HMAC_CTX_init(ctx)
		}
		return ctx
	}
	return C.go_openssl_HMAC_CTX_new()
}

func hmac1CtxReset(ctx C.GO_HMAC_CTX_PTR) {
	if ctx == nil {
		return
	}
	if vMajor == 1 && vMinor == 0 {
		C.go_openssl_HMAC_CTX_cleanup(ctx)
		C.go_openssl_HMAC_CTX_init(ctx)
		return
	}
	C.go_openssl_HMAC_CTX_reset(ctx)
}

func hmac1CtxFree(ctx C.GO_HMAC_CTX_PTR) {
	if ctx == nil {
		return
	}
	if vMajor == 1 && vMinor == 0 {
		C.go_openssl_HMAC_CTX_cleanup(ctx)
		C.free(unsafe.Pointer(ctx))
		return
	}
	C.go_openssl_HMAC_CTX_free(ctx)
}

// hmac3 implements hash.Hash
// using functions available in OpenSSL 3.
type hmac3 struct {
	md        C.GO_EVP_MAC_PTR
	ctx       C.GO_EVP_MAC_CTX_PTR
	params    [2]C.OSSL_PARAM
	size      int
	blockSize int
	key       []byte
	sum       []byte
}

func newHMAC3(key []byte, h hash.Hash, md C.GO_EVP_MD_PTR) *hmac3 {
	mac := C.go_openssl_EVP_MAC_fetch(nil, paramAlgHMAC, nil)
	ctx := C.go_openssl_EVP_MAC_CTX_new(mac)
	if ctx == nil {
		panic("openssl: EVP_MAC_CTX_new failed")
	}
	digest := C.go_openssl_EVP_MD_get0_name(md)
	params := [2]C.OSSL_PARAM{
		C.go_openssl_OSSL_PARAM_construct_utf8_string(paramDigest, digest, 0),
		C.go_openssl_OSSL_PARAM_construct_end(),
	}
	hmac := &hmac3{
		md:        mac,
		ctx:       ctx,
		params:    params,
		size:      h.Size(),
		blockSize: h.BlockSize(),
		key:       key,
	}
	runtime.SetFinalizer(hmac, (*hmac3).finalize)
	hmac.Reset()
	return hmac
}

func (h *hmac3) Reset() {
	if C.go_openssl_EVP_MAC_init(h.ctx, base(h.key), C.size_t(len(h.key)), &h.params[0]) == 0 {
		panic(newOpenSSLError("EVP_MAC_init failed"))
	}
	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *hmac3) finalize() {
	if h.ctx == nil {
		return
	}
	C.go_openssl_EVP_MAC_CTX_free(h.ctx)
}

func (h *hmac3) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.go_openssl_EVP_MAC_update(h.ctx, base(p), C.size_t(len(p)))
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *hmac3) Size() int {
	return h.size
}

func (h *hmac3) BlockSize() int {
	return h.blockSize
}

func (h *hmac3) Sum(in []byte) []byte {
	if h.sum == nil {
		size := h.Size()
		h.sum = make([]byte, size)
	}
	// Make copy of context because Go hash.Hash mandates
	// that Sum has no effect on the underlying stream.
	// In particular it is OK to Sum, then Write more, then Sum again,
	// and the second Sum acts as if the first didn't happen.
	ctx2 := C.go_openssl_EVP_MAC_CTX_dup(h.ctx)
	if ctx2 == nil {
		panic("openssl: EVP_MAC_CTX_dup failed")
	}
	defer C.go_openssl_EVP_MAC_CTX_free(ctx2)
	C.go_openssl_EVP_MAC_final(ctx2, base(h.sum), nil, C.size_t(len(h.sum)))
	return append(in, h.sum...)
}
