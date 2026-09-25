# mkcgo

`mkcgo` generates bindings from the restricted C header syntax used by this repository. By default it emits cgo wrappers and C shims. `-nocgo` emits bindings for the repository's `syscallN` implementation instead.

## Experimental cgo2 backend

`-cgo2` emits two Go source files, with the output name's `_cgo2.go` and `_cgo2_bindings.go` suffixes, containing wrappers and Go-syntax bindings respectively. Constants are included in the binding file. It does not emit C headers, C implementations, assembly, or a separate constants file. Generation itself works with the module's regular Go toolchain.

Building the generated bindings requires `CGO_ENABLED=1`, `GOEXPERIMENT=cgo2`, and a Go toolchain containing the [prototype chain ending at CL 838206, patch set 1](https://go-review.googlesource.com/c/go/+/838206/1) (commit `bee3b1fea0824726292f2417e17a6d74996c0c34`, including CL 837205, patch set 3). This is not a released Go feature. The generated files are constrained to Linux and Darwin on amd64 and arm64, the platforms supported by that prototype. No C compiler is needed to build the generated bindings: cgo generates the ABI trampolines in Go and assembly.

The backend supports:

- `-mode dynamic`: direct `//cgo:binding` declarations for shared-library symbols, including framework imports and extern variables.
- `-mode dynload`: a distinct typed function pointer and `//cgo:funcptr` `Call` method for each function. Non-variadic pointers are converted to their function-specific types when loaded, so wrappers call them without repeated casts. Variadic targets retain one raw symbol address, converted separately for each fixed-signature `Call` binding. The existing `MkcgoLoad_<tag>(handle)` and `MkcgoUnload_<tag>()` API, per-tag symbol aliases, and optional-function availability checks are preserved. A generated binding to `dlsym` resolves symbols from the caller-owned handle; unloading a tag clears its pointers but does not close the library. The prototype's `runtime/cgo.Library` cannot adopt an existing handle, so it cannot replace this API.
- Fixed-signature `variadic` wrappers, including floating-point arguments. `mkcgo` preserves the declared parameter types and emits `//cgo:variadic`; the toolchain applies C's default argument promotions and implements the platform's calling convention.
- Enum constants with explicit `//cgo:binding` annotations, usable through both their generated Go names and `C.<original name>` selectors.
- `noescape`, `nocallback`, `slice`, `noerror`, and `errcond` attributes, typedefs, enums, `-private`, `-noerrors`, `-tags`, and `-copyright`.

As in the nocgo backend, error-enabled wrappers require the containing package to supply `retrieveErrorState() uintptr` and `newMkcgoErr(string, uintptr) error`. The wrapper holds an OS-thread lock for the native call and error handling, including `newMkcgoErr`. A deferred unlock balances the wrapper's lock even on panic, without releasing a caller's outer lock. The retrieval function must not call another error-enabled wrapper that could recursively retrieve the same error state. `-noerrors` removes this requirement. Error conditions must be valid Go comparisons after translation of C `NULL` to `nil`.

Generate into a package without active legacy bindings or C shims. The prototype consumes only one binding descriptor per package; multiple generated binding files cannot currently be combined in the same package. Ordinary Go globals can now coexist with binding declarations, but the generator keeps wrappers and loader state separate. `-tags` also applies to the legacy C implementation, cgo wrappers, and common constants, allowing an alternative backend to exclude them.

`-cgo2` cannot be combined with `-nocgo` or `-include`. All nonstandard types must be declared in the input headers; the backend does not ask a C compiler to discover layouts from includes. Static symbols are unsupported. Optional functions require `-mode dynload`.

Generator tests run with the regular Go toolchain. Additional OpenSSL binding tests are enabled when the test binary is built with the prototype's `cgo2` experiment on Linux. They compile and link the bindings for all four supported targets, then run the real OpenSSL and setup unit tests on the native target with the C compiler disabled.

The prototype has an ARM64 callback-trampoline defect: loading the Go callback entry point clobbers C's callee-saved R27 before saving it. Calling Go callbacks from C is not safe on ARM64 with this revision; this backend does not patch the Go toolchain.

### Real OpenSSL bindings

`go generate ./internal/ossl` also generates the checked-in cgo2 OpenSSL bindings. On the supported platforms, `CGO_ENABLED=1 GOEXPERIMENT=cgo2` selects them instead of the legacy C wrappers. Ordinary cgo and `CGO_ENABLED=0` builds retain their existing backends.

Using the prototype's `go` executable, run `CGO_ENABLED=1 GOEXPERIMENT=cgo2 CC=/bin/false CXX=/bin/false go test -count=1 ./openssl ./osslsetup` to test against an installed OpenSSL shared library without invoking a C compiler. Library selection, optional symbols, and version-specific aliases are unchanged. The loader bindings live in `osslsetup`, separately from the OpenSSL function-pointer bindings in `internal/ossl`. Ordinary cgo and cgo2 share the Unix loader implementation, including `C.RTLD_LAZY | C.RTLD_LOCAL`. Separate Darwin and Linux cgo2 descriptors supply the platform-specific constants and function declarations; ordinary cgo gets them from the system headers. String and byte conversions use the prototype's `C.GoString` and `C.GoBytes` helpers instead of the nocgo implementations.

OpenSSL errors are captured in Go while the generated wrapper holds `runtime.LockOSThread`. The error hook calls the raw `BIO_new` binding to avoid recursive error retrieval on allocation failure. This path does not use `internal/fakecgo`, custom `syscallN` assembly, or the legacy C stack-protector helper. It is experimental: sanitizer compatibility, hardening-policy compatibility, and performance parity with the existing backends are not established.

`TestCgo2OpenSSLPackages` in the prototype-only integration tests links the real OpenSSL and setup test executables for all four supported targets, then runs their unit tests on the native Linux target. `TestCgo2OpenSSL` checks that the checked-in bindings match the generator using the regular Go toolchain.
