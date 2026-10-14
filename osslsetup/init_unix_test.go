// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build unix

package osslsetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildFakeLibcrypto compiles testdata/fakelibcrypto.c into a shared library
// with the given C flags and returns its path.
func buildFakeLibcrypto(t *testing.T, cflags ...string) string {
	t.Helper()
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("C compiler %q not found: %v", cc, err)
	}
	out := filepath.Join(t.TempDir(), "libfakecrypto.so")
	args := append([]string{"-shared", "-fPIC", "-o", out}, cflags...)
	args = append(args, filepath.Join("testdata", "fakelibcrypto.c"))
	if b, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", cc, strings.Join(args, " "), err, b)
	}
	return out
}

// realLibcrypto returns a loadable, supported libcrypto, or "" if none is found.
func realLibcrypto() string {
	candidates := []string{"libcrypto.so.3", "libcrypto.so.1.1"}
	if v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE"); v != "" {
		if runtime.GOOS == "linux" {
			v = "libcrypto.so." + v
		}
		candidates = []string{v}
	}
	for _, v := range candidates {
		if ok, _ := CheckVersion(v); ok {
			return v
		}
	}
	return ""
}

func TestRejectLibrary(t *testing.T) {
	tests := []struct {
		name    string
		cflags  []string
		wantErr string
	}{
		{"versionless", nil, "version not available"},
		{"unsupported 1.0.2", []string{"-DFAKE_VERSION_NUM=0x1000207fUL"}, "1.0.2"},
		// AWS-LC and BoringSSL report 1.1.1 but lack BN_bn2lebinpad.
		{"aws-lc", []string{"-DFAKE_VERSION_NUM=0x1010107fUL"}, "missing BN_bn2lebinpad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib := buildFakeLibcrypto(t, tt.cflags...)
			prevMajor, prevMinor, prevPatch := vMajor, vMinor, vPatch
			t.Cleanup(func() { vMajor, vMinor, vPatch = prevMajor, prevMinor, prevPatch })

			if exists, _ := CheckVersion(lib); exists {
				t.Fatalf("CheckVersion(%q) = true, want false", lib)
			}
			if vMajor != prevMajor || vMinor != prevMinor || vPatch != prevPatch {
				t.Fatalf("CheckVersion left version %d.%d.%d, want %d.%d.%d",
					vMajor, vMinor, vPatch, prevMajor, prevMinor, prevPatch)
			}
			// opensslInit is the body of Init, which can only run once.
			err := opensslInit(lib)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("opensslInit(%q) error = %v, want containing %q", lib, err, tt.wantErr)
			}

			// The rejected library must not break loading a real one.
			real := realLibcrypto()
			if real == "" {
				t.Log("no supported libcrypto found, skipping follow-up check")
				return
			}
			if exists, _ := CheckVersion(real); !exists {
				t.Fatalf("CheckVersion(%q) = false after rejecting %q, want true", real, lib)
			}
		})
	}
}
