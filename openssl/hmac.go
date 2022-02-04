// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"hash"
	"runtime"
	"unsafe"
)

// hashToMD converts a hash.Hash implementation from this package
// to an OpenSSL *C.EVP_MD.
func hashToMD(h hash.Hash) *C.EVP_MD {
	switch h.(type) {
	case *sha1Hash:
		return C.go_openssl_EVP_sha1()
	case *sha224Hash:
		return C.go_openssl_EVP_sha224()
	case *sha256Hash:
		return C.go_openssl_EVP_sha256()
	case *sha384Hash:
		return C.go_openssl_EVP_sha384()
	case *sha512Hash:
		return C.go_openssl_EVP_sha512()
	}
	return nil
}

// cryptoHashToMD converts a crypto.Hash
// to an OpenSSL *C.EVP_MD.
func cryptoHashToMD(ch crypto.Hash) *C.EVP_MD {
	switch ch {
	case crypto.MD5:
		return C.go_openssl_EVP_md5()
	case crypto.MD5SHA1:
		if vMajor == 1 && vMinor == 0 {
			// MD5SHA1 is not implemented in OpenSSL 1.0.2.
			// It is implemented in higher versions but without FIPS support.
			// It is considered a deprecated digest, not approved by FIPS 140-2
			// and only used in pre-TLS 1.2, so we would rather not support it
			// if using 1.0.2 than than implement something that is not properly validated.
			return nil
		}
		return C.go_openssl_EVP_md5_sha1()
	case crypto.SHA1:
		return C.go_openssl_EVP_sha1()
	case crypto.SHA224:
		return C.go_openssl_EVP_sha224()
	case crypto.SHA256:
		return C.go_openssl_EVP_sha256()
	case crypto.SHA384:
		return C.go_openssl_EVP_sha384()
	case crypto.SHA512:
		return C.go_openssl_EVP_sha512()
	}
	return nil
}

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
		// not the behavior previously implemented, so as a workaround
		// we pass an "empty" key.
		hkey = make([]byte, C.EVP_MAX_MD_SIZE)
	}
	hmac := &opensslHMAC{
		md:        md,
		size:      ch.Size(),
		blockSize: ch.BlockSize(),
		key:       hkey,
		ctx:       hmac_ctx_new(),
	}
	runtime.SetFinalizer(hmac, (*opensslHMAC).finalize)
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
	hmac_ctx_reset(h.ctx)

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
	hmac_ctx_free(h.ctx)
}

func (h *opensslHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.go_openssl_HMAC_Update(h.ctx, (*C.uint8_t)(unsafe.Pointer(&p[0])), C.size_t(len(p)))
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
	ctx2 := hmac_ctx_new()
	if C.go_openssl_HMAC_CTX_copy(ctx2, h.ctx) == 0 {
		panic("openssl: HMAC_CTX_copy_ex failed")
	}
	C.go_openssl_HMAC_Final(ctx2, (*C.uint8_t)(unsafe.Pointer(&h.sum[0])), nil)
	hmac_ctx_free(ctx2)
	return append(in, h.sum...)
}

func hmac_ctx_reset(ctx *C.HMAC_CTX) {
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

func hmac_ctx_new() *C.HMAC_CTX {
	if vMajor == 1 && vMinor == 0 {
		// 0x120 is the sizeof value when building against OpenSSL 1.0.2 on Ubuntu 16.04.
		ctx := (*C.HMAC_CTX)(C.malloc(0x120))
		if ctx != nil {
			C.go_openssl_HMAC_CTX_init(ctx)
		}
		return ctx
	}
	return C.go_openssl_HMAC_CTX_new()
}

func hmac_ctx_free(ctx *C.HMAC_CTX) {
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
