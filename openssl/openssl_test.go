// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	err := Init(v)
	if err != nil {
		fmt.Println("skipping on linux platform without OpenSSL")
		os.Exit(0)
	}
	_ = SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	fmt.Println("OpenSSL version:", VersionText())
	fmt.Println("FIPS enabled:", FIPS())
	os.Exit(m.Run())
}
