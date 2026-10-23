// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"bytes"
	"cmp"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/microsoft/go-crypto-openssl/internal/mkcgo"
)

func cgo2TestConfig(t *testing.T, loadMode string) {
	t.Helper()
	oldFile, oldHeader, oldPackage := *fileName, *includeHeader, *packageName
	oldNocgo, oldCgo2, oldMode := *nocgo, *cgo2, *mode
	oldPrivate, oldNoerrors, oldTags := *private, *noerrors, *extratags
	oldCopyright := copyright
	t.Cleanup(func() {
		*fileName, *includeHeader, *packageName = oldFile, oldHeader, oldPackage
		*nocgo, *cgo2, *mode = oldNocgo, oldCgo2, oldMode
		*private, *noerrors, *extratags = oldPrivate, oldNoerrors, oldTags
		copyright = oldCopyright
	})
	*fileName, *includeHeader, *packageName = "zfixture.go", "", "fixture"
	*nocgo, *cgo2, *mode = false, true, loadMode
	*private, *noerrors, *extratags = false, false, ""
	copyright = nil
}

func cgo2TestSource(t *testing.T, header string) *mkcgo.Source {
	t.Helper()
	var src mkcgo.Source
	if err := src.Parse(strings.NewReader(header)); err != nil {
		t.Fatal(err)
	}
	return &src
}

func cgo2TestGenerate(t *testing.T, src *mkcgo.Source) (goSource, bindings []byte) {
	t.Helper()
	var buf, bindingBuf bytes.Buffer
	if err := generateGoCgo2(src, &buf, &bindingBuf); err != nil {
		t.Fatal(err)
	}
	formatted := func(data []byte) []byte {
		t.Helper()
		data, err := format.Source(data)
		if err != nil {
			t.Fatalf("format generated bindings: %v\n%s", err, data)
		}
		return data
	}
	return formatted(buf.Bytes()), formatted(bindingBuf.Bytes())
}

func TestCgo2Signatures(t *testing.T) {
	const header = `
typedef void* PTR;
typedef PTR PTR_ALIAS;
typedef unsigned char* BYTE_PTR;
typedef BYTE_PTR BYTE_PTR_ALIAS;
typedef unsigned int uint_alias;
typedef enum {
	VALUE = 1,
} kind;
void ping(void);
int abs(int) __attribute__((noerror));
PTR_ALIAS alloc(size_t n);
int digest(void *p, size_t len, unsigned int *outlen) __attribute__((slice("p","len"),noescape,nocallback));
void pointers(void **p, size_t len) __attribute__((slice("p","len")));
void byte_aliases(BYTE_PTR_ALIAS p, size_t len) __attribute__((slice("p","len")));
void opaque_bytes(PTR_ALIAS p, size_t len) __attribute__((slice("p","len")));
void pointer_aliases(PTR_ALIAS *p, size_t len) __attribute__((slice("p","len")));
int output(char *p, unsigned int *n) __attribute__((slice("p","n")));
uint_alias number(kind k) __attribute__((noerror));
bool valid(PTR p);
float fractional(double d, float *p) __attribute__((noerror));
int sum(int n, ...);
int sum_ints(int n, signed char a, unsigned char b) __attribute__((variadic("sum"),noescape,nocallback));
int sum_empty(int n) __attribute__((variadic("sum")));
`
	for _, loadMode := range []string{"dynamic", "dynload"} {
		for _, unexported := range []bool{false, true} {
			name := loadMode
			if unexported {
				name += "/private"
			}
			t.Run(name, func(t *testing.T) {
				cgo2TestConfig(t, loadMode)
				*private = unexported
				goSource, bindings := cgo2TestGenerate(t, cgo2TestSource(t, header))
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "bindings.go", bindings, parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				// Bindings are Go declarations. Remove the pseudo-import so the
				// regular type checker can check wrappers and their public API.
				for i, decl := range file.Decls {
					if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.IMPORT && len(gen.Specs) == 1 {
						if gen.Specs[0].(*ast.ImportSpec).Path.Value == `"C"` {
							file.Decls = append(file.Decls[:i], file.Decls[i+1:]...)
							break
						}
					}
				}
				hooks, err := parser.ParseFile(fset, "hooks.go", `package fixture
func retrieveErrorState() uintptr
func newMkcgoErr(string, uintptr) error
`, 0)
				if err != nil {
					t.Fatal(err)
				}
				wrappers, err := parser.ParseFile(fset, "wrappers.go", goSource, parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				cfg := types.Config{Importer: importer.Default()}
				pkg, err := cfg.Check("fixture", fset, []*ast.File{file, wrappers, hooks}, nil)
				if err != nil {
					t.Fatalf("type check bindings: %v\n%s\n%s", err, goSource, bindings)
				}
				for symbol, signature := range map[string]string{
					"ping":            "func()",
					"abs":             "func(_arg0 int32) int32",
					"alloc":           "func(n int) (" + goSymName("PTR_ALIAS") + ", error)",
					"digest":          "func(p []byte, outlen *uint32) (int32, error)",
					"pointers":        "func(p []unsafe.Pointer)",
					"byte_aliases":    "func(p []byte)",
					"opaque_bytes":    "func(p []byte)",
					"pointer_aliases": "func(p []" + goSymName("PTR_ALIAS") + ")",
					"output":          "func(p []byte, n *uint32) (int32, error)",
					"number":          "func(k " + goSymName("kind") + ") " + goSymName("uint_alias"),
					"valid":           "func(p " + goSymName("PTR") + ") (bool, error)",
					"fractional":      "func(d float64, p *float32) float32",
					"sum_ints":        "func(n int32, a int8, b byte) (int32, error)",
					"sum_empty":       "func(n int32) (int32, error)",
				} {
					obj := pkg.Scope().Lookup(goSymName(symbol))
					if obj == nil {
						t.Errorf("missing function %s", symbol)
						continue
					}
					got := types.TypeString(obj.Type(), func(p *types.Package) string {
						if p == pkg {
							return ""
						}
						return p.Name()
					})
					if got != signature {
						t.Errorf("%s: got %s, want %s", symbol, got, signature)
					}
				}
			})
		}
	}
}

func TestCgo2BuildConstraints(t *testing.T) {
	cgo2TestConfig(t, "dynamic")
	*extratags = "custom || other"
	data, _ := cgo2TestGenerate(t, cgo2TestSource(t, "void ping(void);"))
	var expr constraint.Expr
	for _, line := range strings.Split(string(data), "\n") {
		if constraint.IsGoBuild(line) {
			var err error
			expr, err = constraint.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if expr == nil {
		t.Fatal("missing build constraint")
	}
	for _, test := range []struct {
		tags string
		want bool
	}{
		{"cgo goexperiment.cgo2 linux arm64 custom", true},
		{"cgo goexperiment.cgo2 darwin amd64 other", true},
		{"cgo linux arm64 custom", false},
		{"goexperiment.cgo2 linux arm64 custom", false},
		{"cgo goexperiment.cgo2 windows amd64 custom", false},
		{"cgo goexperiment.cgo2 linux 386 custom", false},
		{"cgo goexperiment.cgo2 linux arm64", false},
		{"other", false},
	} {
		tags := strings.Fields(test.tags)
		got := expr.Eval(func(tag string) bool {
			for _, have := range tags {
				if tag == have {
					return true
				}
			}
			return false
		})
		if got != test.want {
			t.Errorf("%q: got %v, want %v", test.tags, got, test.want)
		}
	}
}

func TestCgo2Validation(t *testing.T) {
	for _, test := range []struct {
		name   string
		header string
		setup  func()
		want   string
	}{
		{"nocgo", "", func() { *nocgo = true }, "mutually exclusive"},
		{"mode", "", func() { *mode = "invalid" }, "unsupported cgo2 mode"},
		{"include", "", func() { *includeHeader = "external.h" }, "does not support -include"},
		{"staticFunc", "void f(void) __attribute__((static));", nil, "static function f"},
		{"staticVar", "extern int v __attribute__((static));", nil, "static extern v"},
		{"optional", "int f(void) __attribute__((optional));", func() { *mode = "dynamic" }, "optional functions require"},
		{"unknownType", "missing f(void);", nil, "unsupported cgo2 type"},
		{"unknownParam", "void f(missing p);", nil, "unsupported cgo2 type"},
		{"cyclicType", "typedef B A;\ntypedef A B;", nil, "cyclic cgo2 typedef"},
		{"errorCondition", `int f(void) __attribute__((errcond("? 1 : 0")));`, nil, "unsupported cgo2 error condition"},
		{"variadic", "int f(int a, int b, ...);\nint g(int a) __attribute__((variadic(\"f\")));", nil, "fewer parameters"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cgo2TestConfig(t, "dynload")
			if test.setup != nil {
				test.setup()
			}
			var buf, bindings bytes.Buffer
			err := generateGoCgo2(cgo2TestSource(t, test.header), &buf, &bindings)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
			if buf.Len() != 0 || bindings.Len() != 0 {
				t.Fatal("invalid input produced partial output")
			}
		})
	}
}

func TestCgo2NoErrors(t *testing.T) {
	cgo2TestConfig(t, "dynload")
	*noerrors = true
	data, _ := cgo2TestGenerate(t, cgo2TestSource(t, "int f(void);"))
	for _, unwanted := range []string{"retrieveErrorState", "newMkcgoErr", `"runtime"`} {
		if bytes.Contains(data, []byte(unwanted)) {
			t.Errorf("-noerrors output contains %s", unwanted)
		}
	}
}

func TestCgo2OpenSSL(t *testing.T) {
	cgo2TestConfig(t, "dynload")
	*fileName, *packageName = "zossl.go", "ossl"
	header, err := os.ReadFile(filepath.Join("..", "..", "internal", "ossl", "shims.h"))
	if err != nil {
		t.Fatal(err)
	}
	src := cgo2TestSource(t, string(header))
	slices.SortFunc(src.Funcs, func(a, b *mkcgo.Func) int { return cmp.Compare(a.Name, b.Name) })
	wrappers, bindings := cgo2TestGenerate(t, src)
	for name, want := range map[string][]byte{
		"zossl_cgo2.go":          wrappers,
		"zossl_cgo2_bindings.go": bindings,
	} {
		got, err := os.ReadFile(filepath.Join("..", "..", "internal", "ossl", name))
		if err != nil {
			t.Fatal(err)
		}
		got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run go generate ./internal/ossl", name)
		}
	}
}

func TestLegacyExtraBuildTags(t *testing.T) {
	cgo2TestConfig(t, "dynload")
	*cgo2 = false
	src := cgo2TestSource(t, "enum {\nVALUE = 1,\n};\nint abs(int n);\n")
	for name, generate := range map[string]func(*mkcgo.Source, io.Writer){
		"common": generateGoCommon,
		"cgo":    generateGoCgo,
		"C":      generateC,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tags := range []string{"", "!goexperiment.cgo2", "!goexperiment.cgo2 || !cgo"} {
				*extratags = tags
				var buf bytes.Buffer
				generate(src, &buf)
				var got string
				for _, line := range strings.Split(buf.String(), "\n") {
					if constraint.IsGoBuild(line) {
						if _, err := constraint.Parse(line); err != nil {
							t.Fatal(err)
						}
						got = strings.TrimPrefix(line, "//go:build ")
					}
				}
				if got != tags {
					t.Errorf("build constraint = %q, want %q", got, tags)
				}
			}
		})
	}
}

func TestCgo2Command(t *testing.T) {
	dir := t.TempDir()
	header := filepath.Join(dir, "input.h")
	if err := os.WriteFile(header, []byte("enum {\nVALUE = 1,\n};\nint abs(int n);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "run", ".", "-cgo2", "-noerrors", "-out", filepath.Join(dir, "zfixture.go"), "-package", "fixture", header)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkcgo: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if got := strings.Join(names, ","); got != "input.h,zfixture_cgo2.go,zfixture_cgo2_bindings.go" {
		t.Fatalf("generated files: %s", got)
	}
	data, err := os.ReadFile(filepath.Join(dir, "zfixture_cgo2_bindings.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("VALUE = 1")) {
		t.Fatal("generated bindings are missing enum constants")
	}
}
