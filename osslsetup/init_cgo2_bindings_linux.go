// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build goexperiment.cgo2 && cgo && (amd64 || arm64)

package osslsetup

import "C"
import "unsafe"

// Each platform needs a complete descriptor: the prototype consumes only one
// binding file per package.

//cgo:binding C.RTLD_LAZY
const cgo2RTLDLazy = 1

//cgo:binding C.RTLD_LOCAL
const cgo2RTLDLocal = 0

//cgo:binding C.dlopen
func cgo2Dlopen(path *int8, flags int32) unsafe.Pointer

//cgo:binding C.dlclose
func cgo2Dlclose(handle unsafe.Pointer) int32

//cgo:binding C.dlerror
func cgo2Dlerror() *int8

//cgo:binding C.free
func cgo2Free(ptr unsafe.Pointer)
