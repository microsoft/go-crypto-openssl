// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"bytes"
	"encoding"
	"fmt"
	"hash"
	"io"
	"testing"
)

func TestSha(t *testing.T) {
	msg := []byte("testig")
	var tests = []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha1", NewSHA1},
		{"sha224", NewSHA224},
		{"sha256", NewSHA256},
		{"sha384", NewSHA384},
		{"sha512", NewSHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := tt.fn()
			initSum := h.Sum(nil)
			n, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(msg) {
				t.Errorf("got: %d, want: %d", n, len(msg))
			}
			sum := h.Sum(nil)
			if size := h.Size(); len(sum) != size {
				t.Errorf("got: %d, want: %d", len(sum), size)
			}
			if bytes.Equal(sum, initSum) {
				t.Error("Write didn't change internal hash state")
			}

			state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Errorf("could not marshal: %v", err)
			}
			h2 := tt.fn()
			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
			}
			if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != marshaled 0x%x", actual, actual2)
			}

			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}

			bw := h.(io.ByteWriter)
			for i := 0; i < len(msg); i++ {
				bw.WriteByte(msg[i])
			}
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}

			h.(io.StringWriter).WriteString(string(msg))
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestSHA_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		name    string
		want    func() hash.Hash
		oneShot func([]byte) []byte
	}{
		{"sha1", NewSHA1, func(p []byte) []byte {
			b := SHA1(p)
			return b[:]
		}},
		{"sha224", NewSHA224, func(p []byte) []byte {
			b := SHA224(p)
			return b[:]
		}},
		{"sha256", NewSHA256, func(p []byte) []byte {
			b := SHA256(p)
			return b[:]
		}},
		{"sha384", NewSHA384, func(p []byte) []byte {
			b := SHA384(p)
			return b[:]
		}},
		{"sha512", NewSHA512, func(p []byte) []byte {
			b := SHA512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.oneShot(msg)
			h := tt.want()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got[:], want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

func TestMD5OneShot(t *testing.T) {
	SetFIPS(false)
	fmt.Println("OpenSSL version:", VersionText())
	fmt.Println("FIPS enabled:", FIPS())
	msg := []byte("testing")
	var tests = []struct {
		name    string
		want    func() hash.Hash
		oneShot func([]byte) []byte
	}{
		{"md5", NewMD5, func(p []byte) []byte {
			b := MD5(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.oneShot(msg)
			h := tt.want()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got[:], want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

type cgoData struct {
	Data [16]byte
	Ptr  *cgoData
}

func TestCgo(t *testing.T) {
	// Test that Write does not cause cgo to scan the entire cgoData struct for pointers.
	// The scan (if any) should be limited to the [16]byte.
	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()
	d := new(cgoData)
	d.Ptr = d
	h := NewSHA256()
	h.Write(d.Data[:])
	h.Sum(nil)

	SHA256(d.Data[:])
}

func BenchmarkHash8Bytes(b *testing.B) {
	b.StopTimer()
	h := NewSHA256()
	sum := make([]byte, h.Size())
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(sum[:0])
	}
}

func BenchmarkSHA256(b *testing.B) {
	b.StopTimer()
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SHA256(buf)
	}
}
