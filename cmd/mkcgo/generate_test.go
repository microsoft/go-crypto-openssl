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

func TestGenerateNocgoPointerLifetimes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		attrs string
	}{
		{"escaping", ""},
		{"noescape", ", noescape, nocallback"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var src mkcgo.Source
			err := src.Parse(strings.NewReader(`
typedef void* CONTEXT_PTR;
int example(CONTEXT_PTR ctx, void* opaque, const unsigned char* input, size_t input_len, unsigned char* output, size_t* output_len, int a, int b, int c, int d, int e) __attribute__((noerror, slice(input, input_len), slice(output, output_len)` + tt.attrs + `));
`))
			if err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			generateNocgoFns(&src, &output)
			code := output.String()
			call := strings.LastIndex(code, "syscallN(")
			ret := strings.LastIndex(code, "return ")
			if call < 0 || ret < call || !strings.Contains(code, `runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"`) {
				t.Fatalf("missing syscall or Darwin ARM64 argument handling:\n%s", code)
			}
			for _, param := range []string{"ctx", "opaque", "input", "output", "output_len"} {
				keepAlive := "runtime.KeepAlive(" + param + ")"
				pos := strings.Index(code, keepAlive)
				if pos < call || pos > ret || strings.Count(code, keepAlive) != 1 {
					t.Errorf("%s must occur once after all syscall paths and before the return", keepAlive)
				}
			}
			for _, param := range []string{"input_len", "a", "b", "c", "d", "e"} {
				if strings.Contains(code, "runtime.KeepAlive("+param+")") {
					t.Errorf("unexpected KeepAlive for scalar parameter %s", param)
				}
			}
		})
	}
}
