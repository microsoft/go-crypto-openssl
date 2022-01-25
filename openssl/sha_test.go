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
	for i, fn := range []func() hash.Hash{NewSHA1, NewSHA224, NewSHA256, NewSHA384, NewSHA512} {
		h := fn()
		initSum := h.Sum(nil)
		n, err := h.Write(msg)
		if err != nil {
			t.Errorf("i %d: %v", i, err)
			continue
		}
		if n != len(msg) {
			t.Errorf("i %d: got: %d, want: %d", i, n, len(msg))
		}
		sum := h.Sum(nil)
		if size := h.Size(); len(sum) != size {
			t.Errorf("i %d: got: %d, want: %d", i, len(sum), size)
		}
		if bytes.Equal(sum, initSum) {
			t.Errorf("i %d: Write didn't change internal hash state", i)
		}

		state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			t.Errorf("i: %d: could not marshal: %v", i, err)
		}
		h2 := fn()
		if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			t.Errorf("i: %d: could not unmarshal: %v", i, err)
		}
		if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
			t.Errorf("i: %d = 0x%x != marshaled 0x%x", i, actual, actual2)
		}

		h.Reset()
		sum = h.Sum(nil)
		if !bytes.Equal(sum, initSum) {
			t.Errorf("i %d: got:%x want:%x", i, sum, initSum)
		}
	}
}
