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
		hkey = make([]byte, C.EVP_MAX_MD_SIZE)
	}
	hmac := &opensslHMAC{
		md:        md,
		size:      ch.Size(),
		blockSize: ch.BlockSize(),
		key:       hkey,
		ctx:       C.go_openssl_HMAC_CTX_new(),
	}
	hmac.Reset()
	return hmac
}

type opensslHMAC struct {
	md        *C.EVP_MD
	ctx       *C.HMAC_CTX
	size      int
	blockSize int
	key       []byte
	sum       []byte
}

func (h *opensslHMAC) Reset() {
	C.go_openssl_HMAC_CTX_reset(h.ctx)

	if C.go_openssl_HMAC_Init_ex(h.ctx, unsafe.Pointer(base(h.key)), C.int(len(h.key)), h.md, nil) == 0 {
		panic("openssl: HMAC_Init failed")
	}
	if size := int(C.go_openssl_EVP_MD_get_size(h.md)); size != h.size {
		println("openssl: HMAC size:", size, "!=", h.size)
		panic("openssl: HMAC size mismatch")
	}
	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *opensslHMAC) finalize() {
	C.go_openssl_HMAC_CTX_free(h.ctx)
}

func (h *opensslHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.go_openssl_HMAC_Update(h.ctx, base(p), C.size_t(len(p)))
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *opensslHMAC) Size() int {
	return h.size
}

func (h *opensslHMAC) BlockSize() int {
	return h.blockSize
}

func (h *opensslHMAC) Sum(in []byte) []byte {
	if h.sum == nil {
		size := h.Size()
		h.sum = make([]byte, size)
	}
	// Make copy of context because Go hash.Hash mandates
	// that Sum has no effect on the underlying stream.
	// In particular it is OK to Sum, then Write more, then Sum again,
	// and the second Sum acts as if the first didn't happen.
	ctx2 := C.go_openssl_HMAC_CTX_new()
	if C.go_openssl_HMAC_CTX_copy(ctx2, h.ctx) == 0 {
		panic("openssl: HMAC_CTX_copy failed")
	}
	C.go_openssl_HMAC_Final(ctx2, base(h.sum), nil)
	C.go_openssl_HMAC_CTX_free(ctx2)
	return append(in, h.sum...)
}
