// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build goexperiment.cgo2 && linux && (amd64 || arm64)

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCgo2OpenSSLBindings(t *testing.T) {
	cgo2TestConfig(t, "dynload")
	header, err := os.ReadFile(filepath.Join("..", "..", "internal", "ossl", "shims.h"))
	if err != nil {
		t.Fatal(err)
	}
	goSource, bindings := cgo2TestGenerate(t, cgo2TestSource(t, string(header)))
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"go.mod":      []byte("module fixture\n\ngo 1.26\n"),
		"wrappers.go": goSource,
		"bindings.go": bindings,
		"hooks.go": []byte(`package fixture
func retrieveErrorState() uintptr { panic("compile-only error hook") }
func newMkcgoErr(string, uintptr) error { panic("compile-only error hook") }
`),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range [][2]string{{"linux", "arm64"}, {"linux", "amd64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		t.Run(target[0]+"/"+target[1], func(t *testing.T) {
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS="+target[0], "GOARCH="+target[1], "CGO_ENABLED=1", "GOEXPERIMENT=cgo2", "CC=/bin/false", "CXX=/bin/false", "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("compile OpenSSL bindings: %v\n%s", err, out)
			}
		})
	}
}

// TestCgo2OpenSSLPackages exercises the checked-in bindings and handwritten
// loader/error hooks, not just an isolated compile-only binding fixture.
func TestCgo2OpenSSLPackages(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, targetOS, targetArch string, args ...string) {
		t.Helper()
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS="+targetOS, "GOARCH="+targetArch,
			"CGO_ENABLED=1", "GOEXPERIMENT=cgo2", "CC=/bin/false", "CXX=/bin/false", "GOWORK=off")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range [][2]string{{"linux", "arm64"}, {"linux", "amd64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		t.Run(target[0]+"/"+target[1], func(t *testing.T) {
			// Link real test executables too: go build of a non-main package
			// does not exercise native symbol resolution in the Go linker.
			run(t, target[0], target[1], "test", "-c", "-o", t.TempDir()+string(filepath.Separator), "./openssl", "./osslsetup")
		})
	}
	t.Run("native", func(t *testing.T) {
		run(t, runtime.GOOS, runtime.GOARCH, "test", "-count=1", "./openssl", "./osslsetup")
	})
}
