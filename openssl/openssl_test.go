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
	err := Init()
	if err != nil {
		fmt.Println("skipping on linux platform without OpenSSL")
		os.Exit(0)
	}
	_ = SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	os.Exit(m.Run())
}
