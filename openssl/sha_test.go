// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"bytes"
	"encoding"
	"hash"
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
		})
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	b.StopTimer()
	h := NewSHA256()
	sum := make([]byte, h.Size())
	buf := make([]byte, 8192)
	size := 1024
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf[:size])
		h.Sum(sum[:0])
	}
}
