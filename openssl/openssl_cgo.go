// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package openssl

import "C"
import "unsafe"

// The binding annotations select cgo2 while preserving these shared Go bodies.

// goString converts a C string pointer to a Go string for cgo mode
//
//cgo:binding C.GoString
func goString(ptr *byte) string {
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}

// goBytes converts a C byte array to a Go byte slice for cgo mode
//
//cgo:binding C.GoBytes
func goBytes(ptr unsafe.Pointer, length int) []byte {
	return C.GoBytes(ptr, C.int(length))
}
