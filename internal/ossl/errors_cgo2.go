// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build goexperiment.cgo2 && cgo && (linux || darwin) && (amd64 || arm64)

package ossl

// retrieveErrorState drains OpenSSL's thread-local error queue. The generated
// wrapper keeps the goroutine locked to the calling OS thread until this returns.
func retrieveErrorState() uintptr {
	// Call BIO_new directly: its error-enabled wrapper would recursively try
	// to retrieve the error state if allocating the memory BIO failed.
	bio := _mkcgo_BIO_new.Call(BIO_s_mem())
	if bio == nil {
		panic("openssl: failed to allocate error BIO")
	}
	ERR_print_errors(bio)
	return uintptr(bio)
}
