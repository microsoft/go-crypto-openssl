// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPPC64LEOutput(t *testing.T) {
	const helperEnv = "GO_MKCGO_TEST_PPC64LE_OUTPUT"
	if os.Getenv(helperEnv) == "1" {
		os.Args = append([]string{os.Args[0]}, flag.Args()...)
		main()
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		flag string
		want bool
	}{
		{"default", "", true},
		{"enabled", "-ppc64le=true", true},
		{"disabled", "-ppc64le=false", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			header := filepath.Join(dir, "example.h")
			if err := os.WriteFile(header, []byte("void example(void);\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-test.run=^TestPPC64LEOutput$", "--",
				"-out", "zexample.go",
				"-package", "example", "-nocgo", "-noerrors"}
			if tt.flag != "" {
				args = append(args, tt.flag)
			}
			args = append(args, header)
			cmd := exec.Command(exe, args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), helperEnv+"=1")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("mkcgo: %v\n%s", err, output)
			}
			for _, name := range []string{"zexample_nocgo.go", "zexample.s"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Errorf("missing generated file %s: %v", name, err)
				}
			}
			_, err := os.Stat(filepath.Join(dir, "zexample_ppc64le.s"))
			if tt.want && err != nil {
				t.Fatalf("missing PPC64LE assembly: %v", err)
			}
			if !tt.want && !os.IsNotExist(err) {
				t.Fatalf("PPC64LE output was not disabled: stat error = %v", err)
			}
		})
	}
}
