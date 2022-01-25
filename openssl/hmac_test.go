// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"bytes"
	"hash"
	"testing"
)

func TestHMAC(t *testing.T) {
	for i, fn := range []func() hash.Hash{NewSHA1, NewSHA224, NewSHA256, NewSHA384, NewSHA512} {
		h := NewHMAC(fn, nil)
		h.Write([]byte("hello"))
		sumHello := h.Sum(nil)

		h = NewHMAC(fn, nil)
		h.Write([]byte("hello world"))
		sumHelloWorld := h.Sum(nil)

		// Test that Sum has no effect on future Sum or Write operations.
		// This is a bit unusual as far as usage, but it's allowed
		// by the definition of Go hash.Hash, and some clients expect it to work.
		h = NewHMAC(fn, nil)
		h.Write([]byte("hello"))
		if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
			t.Fatalf("i %d: 1st Sum after hello = %x, want %x", i, sum, sumHello)
		}
		if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
			t.Fatalf("i %d: 2nd Sum after hello = %x, want %x", i, sum, sumHello)
		}

		h.Write([]byte(" world"))
		if sum := h.Sum(nil); !bytes.Equal(sum, sumHelloWorld) {
			t.Fatalf("i %d: 1st Sum after hello world = %x, want %x", i, sum, sumHelloWorld)
		}
		if sum := h.Sum(nil); !bytes.Equal(sum, sumHelloWorld) {
			t.Fatalf("i %d: 2nd Sum after hello world = %x, want %x", i, sum, sumHelloWorld)
		}

		h.Reset()
		h.Write([]byte("hello"))
		if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
			t.Fatalf("i %d: Sum after Reset + hello = %x, want %x", i, sum, sumHello)
		}
	}
}
