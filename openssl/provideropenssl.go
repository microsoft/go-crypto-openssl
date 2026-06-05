// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package openssl

import (
	"crypto"
	"errors"
	"unsafe"

	"github.com/microsoft/go-crypto-openssl/internal/ossl"
)

// This file contains code specific to the built-in OpenSSL providers.

// _OSSL_MD5_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/md5.h#L33.
type _OSSL_MD5_CTX struct {
	h      [4]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (d *_OSSL_MD5_CTX) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *_OSSL_MD5_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// _OSSL_SHA_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L34.
type _OSSL_SHA_CTX struct {
	h      [5]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (d *_OSSL_SHA_CTX) UnmarshalBinary(b []byte) error {
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

func (d *_OSSL_SHA_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = appendUint32(buf, d.h[4])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// _OSSL_SHA256_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L51.
type _OSSL_SHA256_CTX struct {
	h      [8]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
	mdLen  uint32
}

func (d *_OSSL_SHA256_CTX) UnmarshalBinary(b []byte) error {
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

func (d *_OSSL_SHA256_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = appendUint32(buf, d.h[4])
	buf = appendUint32(buf, d.h[5])
	buf = appendUint32(buf, d.h[6])
	buf = appendUint32(buf, d.h[7])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// _OSSL_SHA512_CTX layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L95.
type _OSSL_SHA512_CTX struct {
	h      [8]uint64
	nl, nh uint64
	x      [128]byte
	nx     uint32
	mdLen  uint32
}

func (d *_OSSL_SHA512_CTX) UnmarshalBinary(b []byte) error {
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

func (d *_OSSL_SHA512_CTX) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint64(buf, d.h[0])
	buf = appendUint64(buf, d.h[1])
	buf = appendUint64(buf, d.h[2])
	buf = appendUint64(buf, d.h[3])
	buf = appendUint64(buf, d.h[4])
	buf = appendUint64(buf, d.h[5])
	buf = appendUint64(buf, d.h[6])
	buf = appendUint64(buf, d.h[7])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, d.nl>>3|d.nh<<61)
	return buf, nil
}

func getOSSLDigetsContext(ctx ossl.EVP_MD_CTX_PTR) unsafe.Pointer {
	switch major() {
	case 1:
		// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/crypto/evp/evp_local.h#L12.
		type mdCtx struct {
			_       [2]unsafe.Pointer
			_       uint32
			md_data unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).md_data
	case 3:
		// The EVP_MD_CTX memory layout has changed in OpenSSL 3
		// and the property holding the internal structure is no longer md_data but algctx.
		// https://github.com/openssl/openssl/blob/5675a5aaf6a2e489022bcfc18330dae9263e598e/crypto/evp/evp_local.h#L16.
		type mdCtx struct {
			_      [3]unsafe.Pointer
			_      uint32
			_      [3]unsafe.Pointer
			algctx unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).algctx
	case 4:
		// OpenSSL 4 removed the ENGINE, md_data, and update fields from EVP_MD_CTX.
		// https://github.com/openssl/openssl/blob/openssl-4.0.0-alpha1/crypto/evp/evp_local.h
		type mdCtx struct {
			_      [2]unsafe.Pointer // reqdigest, digest
			_      uint32            // flags
			_      unsafe.Pointer    // pctx
			algctx unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).algctx
	default:
		// Unknown OpenSSL major: the EVP_MD_CTX internal layout is not
		// known, so the running hash state cannot be safely extracted.
		// loadHash marks hashes as not marshallable on untested majors
		// (see evp.go), so MarshalBinary/UnmarshalBinary short-circuit
		// with errMarshallUnsupported{} before calling this. The nil
		// return is defense in depth against any future caller that
		// bypasses that gate.
		return nil
	}
}

var errHashStateInvalid = errors.New("openssl: can't retrieve hash state")

func osslHashAppendBinary(ctx ossl.EVP_MD_CTX_PTR, ch crypto.Hash, magic string, buf []byte) ([]byte, error) {
	algctx := getOSSLDigetsContext(ctx)
	if algctx == nil {
		return nil, errHashStateInvalid
	}
	buf = append(buf, magic...)
	switch ch {
	case crypto.MD5:
		d := (*_OSSL_MD5_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	case crypto.SHA1:
		d := (*_OSSL_SHA_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	case crypto.SHA224, crypto.SHA256:
		d := (*_OSSL_SHA256_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		d := (*_OSSL_SHA512_CTX)(unsafe.Pointer(algctx))
		return d.AppendBinary(buf)
	default:
		panic("unsupported hash " + ch.String())
	}
}

func osslHashUnmarshalBinary(ctx ossl.EVP_MD_CTX_PTR, ch crypto.Hash, magic string, b []byte) error {
	algctx := getOSSLDigetsContext(ctx)
	if algctx == nil {
		return errHashStateInvalid
	}
	b = b[len(magic):]
	switch ch {
	case crypto.MD5:
		d := (*_OSSL_MD5_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	case crypto.SHA1:
		d := (*_OSSL_SHA_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	case crypto.SHA224, crypto.SHA256:
		d := (*_OSSL_SHA256_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		d := (*_OSSL_SHA512_CTX)(unsafe.Pointer(algctx))
		return d.UnmarshalBinary(b)
	default:
		panic("unsupported hash " + ch.String())
	}
}

// OpenSSL 4 serialized format constants.
// See https://github.com/openssl/openssl/blob/openssl-4.0.0/providers/implementations/digests/sha2_prov.c.
var (
	sha256SerializeMagic = [8]byte{'S', 'H', 'A', '2', '5', '6', 'v', '1'}
	sha512SerializeMagic = [8]byte{'S', 'H', 'A', '5', '1', '2', 'v', '1'}
)

const (
	// SHA-256 serialized: magic(8) + md_len(4) + num(4) + h[8](32) + Nl(4) + Nh(4) + data[16](64) = 120
	sha256SerializeLen = 8 + 4 + 4 + 8*4 + 4 + 4 + 16*4
	// SHA-512 serialized: magic(8) + md_len(4) + num(4) + h[8](64) + Nl(8) + Nh(8) + data(128) = 224
	sha512SerializeLen = 8 + 4 + 4 + 8*8 + 8 + 8 + 128
)

// zeroBlock is used for zero-padding the data buffer without allocating.
var zeroBlock [128]byte

// osslHashSerializedAppendBinary converts the serialized hash state obtained
// from EVP_MD_CTX_serialize into Go's standard hash binary format.
// The serialized data for the default and FIPS providers uses a versioned
// format with a magic header (e.g. "SHA256v1") followed by the hash state
// fields in little-endian byte order.
func osslHashSerializedAppendBinary(serialized []byte, ch crypto.Hash, buf []byte) ([]byte, error) {
	switch ch {
	case crypto.SHA224, crypto.SHA256:
		return sha256SerializedAppendBinary(serialized, buf)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		return sha512SerializedAppendBinary(serialized, buf)
	default:
		// MD5, SHA-1, etc. don't support serialize in OpenSSL 4.
		panic("unsupported hash for serialize: " + ch.String())
	}
}

func sha256SerializedAppendBinary(serialized []byte, buf []byte) ([]byte, error) {
	if len(serialized) < sha256SerializeLen {
		return nil, errHashStateInvalid
	}
	p := serialized[8:] // skip magic
	_ = leU32(p)        // md_len, already known
	p = p[4:]
	num := leU32(p)
	p = p[4:]
	// h[0..7] as big-endian (Go format)
	for i := 0; i < 8; i++ {
		buf = appendUint32(buf, leU32(p))
		p = p[4:]
	}
	// Buffer: stored as 16 × uint32 LE, copy as raw bytes.
	// First include Nl, Nh (skip for now, we need them for the length).
	nl := leU32(p)
	p = p[4:]
	nh := leU32(p)
	p = p[4:]
	// data buffer: copy only num valid bytes, zero-pad to 64.
	buf = append(buf, p[:num]...)
	buf = append(buf, zeroBlock[:64-num]...)
	// Byte count from bit count: len = Nl>>3 | Nh<<29
	buf = appendUint64(buf, uint64(nl)>>3|uint64(nh)<<29)
	return buf, nil
}

func sha512SerializedAppendBinary(serialized []byte, buf []byte) ([]byte, error) {
	if len(serialized) < sha512SerializeLen {
		return nil, errHashStateInvalid
	}
	p := serialized[8:] // skip magic
	_ = leU32(p)        // md_len
	p = p[4:]
	num := leU32(p)
	p = p[4:]
	// h[0..7] as big-endian uint64 (Go format)
	for i := 0; i < 8; i++ {
		buf = appendUint64(buf, leU64(p))
		p = p[8:]
	}
	// Nl, Nh
	nl := leU64(p)
	p = p[8:]
	nh := leU64(p)
	p = p[8:]
	// data buffer: copy only num valid bytes, zero-pad to 128.
	buf = append(buf, p[:num]...)
	buf = append(buf, zeroBlock[:128-num]...)
	// Byte count from bit count: len = Nl>>3 | Nh<<61
	buf = appendUint64(buf, nl>>3|nh<<61)
	return buf, nil
}

// osslHashBuildSerialized constructs a serialized hash state from Go's standard
// hash binary format. The result can be passed to EVP_MD_CTX_deserialize.
// The produced blob uses OpenSSL 4's versioned format.
func osslHashBuildSerialized(ch crypto.Hash, b []byte, out []byte) ([]byte, error) {
	switch ch {
	case crypto.SHA224, crypto.SHA256:
		return sha256BuildSerialized(ch, b, out)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		return sha512BuildSerialized(ch, b, out)
	default:
		panic("unsupported hash for serialize: " + ch.String())
	}
}

func sha256BuildSerialized(ch crypto.Hash, b []byte, out []byte) ([]byte, error) {
	out = append(out, sha256SerializeMagic[:]...)
	out = putLeU32(out, uint32(ch.Size())) // md_len
	// Parse Go format: h[0..7] (BE uint32), buffer[64], length (BE uint64)
	var h [8]uint32
	for i := range h {
		b, h[i] = consumeUint32(b)
	}
	xbuf := b[:64]
	b = b[64:]
	_, byteLen := consumeUint64(b)
	num := uint32(byteLen) % 64
	out = putLeU32(out, num) // num
	for _, v := range h {
		out = putLeU32(out, v)
	}
	// Nl, Nh: bit count from byte count
	nl := uint32(byteLen << 3)
	nh := uint32(byteLen >> 29)
	out = putLeU32(out, nl)
	out = putLeU32(out, nh)
	// data buffer: copy full 64 bytes
	out = append(out, xbuf...)
	return out, nil
}

func sha512BuildSerialized(ch crypto.Hash, b []byte, out []byte) ([]byte, error) {
	out = append(out, sha512SerializeMagic[:]...)
	out = putLeU32(out, uint32(ch.Size())) // md_len
	// Parse Go format: h[0..7] (BE uint64), buffer[128], length (BE uint64)
	var h [8]uint64
	for i := range h {
		b, h[i] = consumeUint64(b)
	}
	xbuf := b[:128]
	b = b[128:]
	_, byteLen := consumeUint64(b)
	num := uint32(byteLen) % 128
	out = putLeU32(out, num) // num
	for _, v := range h {
		out = putLeU64(out, v)
	}
	// Nl, Nh: bit count from byte count
	nl := byteLen << 3
	nh := byteLen >> 61
	out = putLeU64(out, nl)
	out = putLeU64(out, nh)
	// data buffer
	out = append(out, xbuf...)
	return out, nil
}

// Little-endian binary helpers.

func leU32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leU64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func putLeU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func putLeU64(b []byte, v uint64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

// structBytes returns a new byte slice containing a copy of the struct at ptr.
func structBytes(ptr unsafe.Pointer, size uintptr) []byte {
	out := make([]byte, size)
	copy(out, unsafe.Slice((*byte)(ptr), size))
	return out
}
