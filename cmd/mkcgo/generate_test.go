// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"strings"
	"testing"

	"github.com/microsoft/go-crypto-openssl/internal/mkcgo"
)

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
int example(CONTEXT_PTR ctx, void* opaque, const unsigned char* input, size_t input_len, unsigned char* output, size_t* output_len, int a, int b, int c, int d, int e) __attribute__((noerror, slice(input, input_len)` + tt.attrs + `));
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
