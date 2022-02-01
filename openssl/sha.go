// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"unsafe"
)

type evpHash struct {
	md        *C.EVP_MD
	ctx       *C.EVP_MD_CTX
	ctx2      *C.EVP_MD_CTX
	size      int
	blockSize int
}

func newEvpHash(ch crypto.Hash, size, blockSize int) *evpHash {
	md := cryptoHashToMD(ch)
	if md == nil {
		panic("openssl: unsupported hash function: " + strconv.Itoa(int(ch)))
	}
	ctx := C.go_openssl_EVP_MD_CTX_new()
	ctx2 := C.go_openssl_EVP_MD_CTX_new()
	h := &evpHash{
		md:        md,
		ctx:       ctx,
		ctx2:      ctx2,
		size:      size,
		blockSize: blockSize,
	}
	runtime.SetFinalizer(h, (*evpHash).finalize)
	h.Reset()
	return h
}

func (h *evpHash) finalize() {
	C.go_openssl_EVP_MD_CTX_free(h.ctx)
	C.go_openssl_EVP_MD_CTX_free(h.ctx2)
}

func (h *evpHash) Reset() {
	C.go_openssl_EVP_MD_CTX_reset(h.ctx)

	if C.go_openssl_EVP_DigestInit_ex(h.ctx, h.md, nil) != 1 {
		panic("openssl: EVP_DigestInit_ex failed")
	}
	runtime.KeepAlive(h)
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) > 0 && C.go_openssl_EVP_DigestUpdate(h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) != 1 {
		panic("openssl: EVP_DigestUpdate failed")
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *evpHash) Size() int {
	return h.size
}

func (h *evpHash) BlockSize() int {
	return h.blockSize
}

func (h *evpHash) sum(out []byte) {
	// Make copy of context because Go hash.Hash mandates
	// that Sum has no effect on the underlying stream.
	// In particular it is OK to Sum, then Write more, then Sum again,
	// and the second Sum acts as if the first didn't happen.
	C.go_openssl_EVP_DigestInit_ex(h.ctx2, h.md, nil)
	if C.go_openssl_EVP_MD_CTX_copy_ex(h.ctx2, h.ctx) != 1 {
		panic("openssl: EVP_MD_CTX_copy_ex failed")
	}
	if C.go_openssl_EVP_DigestFinal_ex(h.ctx2, (*C.uint8_t)(unsafe.Pointer(&out[0])), nil) != 1 {
		panic("openssl: EVP_DigestFinal_ex failed")
	}
	C.go_openssl_EVP_MD_CTX_reset(h.ctx2)
	runtime.KeepAlive(h)
}

// shaCtx returns a pointer to the internal sha structure.
//
// The EVP_MD_CTX memory layout has changed in OpenSSL 3
// and the property holding the internal structure is no longer md_data but algctx.
func (h *evpHash) shaCtx() unsafe.Pointer {
	switch vMajor {
	case 1:
		type mdCtx struct {
			_       [2]unsafe.Pointer
			_       C.ulong
			md_data unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(h.ctx)).md_data
	case 3:
		type mdCtx struct {
			_      [3]unsafe.Pointer
			_      C.ulong
			_      [3]unsafe.Pointer
			algctx unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(h.ctx)).algctx
	default:
		panic(errUnsuportedVersion())
	}
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return &sha1Hash{
		evpHash: newEvpHash(crypto.SHA1, 20, 64),
	}
}

type sha1Hash struct {
	*evpHash
	out [20]byte
}

func (h *sha1Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

type sha1Ctx struct {
	h      [5]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

const (
	sha1Magic         = "sha\x01"
	sha1MarshaledSize = len(sha1Magic) + 5*4 + 64 + 8
)

func (h *sha1Hash) MarshalBinary() ([]byte, error) {
	d := (*sha1Ctx)(h.shaCtx())
	b := make([]byte, 0, sha1MarshaledSize)
	b = append(b, sha1Magic...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha1Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(sha1Magic) || string(b[:len(sha1Magic)]) != sha1Magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != sha1MarshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	d := (*sha1Ctx)(h.shaCtx())
	b = b[len(sha1Magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	return &sha224Hash{
		evpHash: newEvpHash(crypto.SHA224, 224/8, 64),
	}
}

type sha224Hash struct {
	*evpHash
	out [224 / 8]byte
}

func (h *sha224Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return &sha256Hash{
		evpHash: newEvpHash(crypto.SHA256, 256/8, 64),
	}
}

type sha256Hash struct {
	*evpHash
	out [256 / 8]byte
}

func (h *sha256Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

const (
	magic224         = "sha\x02"
	magic256         = "sha\x03"
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8
)

type sha256Ctx struct {
	h      [8]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (h *sha224Hash) MarshalBinary() ([]byte, error) {
	d := (*sha256Ctx)(h.shaCtx())
	b := make([]byte, 0, marshaledSize256)
	b = append(b, magic224...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha256Hash) MarshalBinary() ([]byte, error) {
	d := (*sha256Ctx)(h.shaCtx())
	b := make([]byte, 0, marshaledSize256)
	b = append(b, magic256...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha224Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic224) || string(b[:len(magic224)]) != magic224 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256Ctx)(h.shaCtx())
	b = b[len(magic224):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (h *sha256Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic256) || string(b[:len(magic256)]) != magic256 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256Ctx)(h.shaCtx())
	b = b[len(magic256):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return &sha384Hash{
		evpHash: newEvpHash(crypto.SHA384, 384/8, 128),
	}
}

type sha384Hash struct {
	*evpHash
	out [384 / 8]byte
}

func (h *sha384Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return &sha512Hash{
		evpHash: newEvpHash(crypto.SHA512, 512/8, 128),
	}
}

type sha512Hash struct {
	*evpHash
	out [512 / 8]byte
}

func (h *sha512Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

type sha512Ctx struct {
	h      [8]uint64
	nl, nh uint64
	x      [128]byte
	nx     uint32
}

const (
	magic384         = "sha\x04"
	magic512_224     = "sha\x05"
	magic512_256     = "sha\x06"
	magic512         = "sha\x07"
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8
)

var zero [128]byte

func (h *sha384Hash) MarshalBinary() ([]byte, error) {
	d := (*sha512Ctx)(h.shaCtx())
	b := make([]byte, 0, marshaledSize512)
	b = append(b, magic384...)
	b = appendUint64(b, d.h[0])
	b = appendUint64(b, d.h[1])
	b = appendUint64(b, d.h[2])
	b = appendUint64(b, d.h[3])
	b = appendUint64(b, d.h[4])
	b = appendUint64(b, d.h[5])
	b = appendUint64(b, d.h[6])
	b = appendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha512Hash) MarshalBinary() ([]byte, error) {
	d := (*sha512Ctx)(h.shaCtx())
	b := make([]byte, 0, marshaledSize512)
	b = append(b, magic512...)
	b = appendUint64(b, d.h[0])
	b = appendUint64(b, d.h[1])
	b = appendUint64(b, d.h[2])
	b = appendUint64(b, d.h[3])
	b = appendUint64(b, d.h[4])
	b = appendUint64(b, d.h[5])
	b = appendUint64(b, d.h[6])
	b = appendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha384Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic384)]) != magic384 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512Ctx)(h.shaCtx())
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func (h *sha512Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic512)]) != magic512 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512Ctx)(h.shaCtx())
	b = b[len(magic512):]
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	putUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	putUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

func putUint64(x []byte, s uint64) {
	_ = x[7]
	x[0] = byte(s >> 56)
	x[1] = byte(s >> 48)
	x[2] = byte(s >> 40)
	x[3] = byte(s >> 32)
	x[4] = byte(s >> 24)
	x[5] = byte(s >> 16)
	x[6] = byte(s >> 8)
	x[7] = byte(s)
}

func putUint32(x []byte, s uint32) {
	_ = x[3]
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}
