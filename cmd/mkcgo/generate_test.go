// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"strings"
	"testing"

	"github.com/microsoft/go-crypto-openssl/internal/mkcgo"
)

func TestGenerateAssemblyPPC64LETrampoline(t *testing.T) {
	var output strings.Builder
	generateAssembly(&mkcgo.Source{
		Funcs: []*mkcgo.Func{{Name: "example"}},
	}, &output, true)

	const want = `TEXT _mkcgo_example_trampoline<>(SB), NOSPLIT, $0-0
	CALL _mkcgo_example(SB)
	// The NOP is the TOC restore slot. The linker rewrites it to
	// MOVD 24(R1), R2 when linking PIC code.
	WORD $0x60000000
	RET`
	if !strings.Contains(output.String(), "//go:build !cgo\n") ||
		!strings.Contains(output.String(), "#define _GOPTRSIZE 8") ||
		!strings.Contains(output.String(), want) ||
		strings.Contains(output.String(), "#ifndef GOARCH_") {
		t.Fatalf("generated assembly does not contain PPC64LE trampoline:\n%s", output.String())
	}
}

func TestGenerateAssemblyOtherTrampoline(t *testing.T) {
	var output strings.Builder
	generateAssembly(&mkcgo.Source{
		Funcs: []*mkcgo.Func{{Name: "example"}},
	}, &output, false)

	const want = `TEXT _mkcgo_example_trampoline<>(SB), NOSPLIT, $0-0
	JMP _mkcgo_example(SB)`
	if !strings.Contains(output.String(), "//go:build !cgo && !ppc64le") ||
		!strings.Contains(output.String(), want) {
		t.Fatalf("generated assembly does not contain non-PPC64LE trampoline:\n%s", output.String())
	}
}
