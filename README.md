# go-crypto-openssl

[![Go Reference](https://pkg.go.dev/badge/github.com/microsoft/go-crypto-openssl/openssl.svg)](https://pkg.go.dev/github.com/microsoft/go-crypto-openssl/openssl)

The `openssl` package implements Go crypto primitives using OpenSSL shared libraries and cgo. When configured correctly, OpenSSL can be executed in FIPS mode, making the `openssl` package FIPS compliant.

The `openssl` package is designed to be used as a drop-in replacement for the [boring](https://pkg.go.dev/crypto/internal/boring) package in order to facilitate integrating `openssl` inside a forked Go toolchain.

> [!IMPORTANT]
> Starting with Go 1.21, the [Microsoft build of Go](https://github.com/microsoft/go) uses [golang-fips/openssl](https://github.com/golang-fips/openssl) instead of this module.
>
> This module was used by the Microsoft build of Go in 1.20 and earlier.
> These versions are all unsupported as of 2024-02-06.

## Disclaimer

A program directly or indirectly using this package in FIPS mode can claim it is using a FIPS-certified cryptographic module (OpenSSL), but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Background

See [the golang-fips/openssl README.md](https://github.com/golang-fips/openssl/blob/v2/README.md) for more information about the history and motivation behind this package.

## Features

### Multiple OpenSSL versions supported

The `openssl` package has support for multiple OpenSSL versions.

OpenSSL versions 1.0.2, 1.1.0, 1.1.1 and 3.0.1 pass a small set of automatic tests that ensure they can be built and that there are no major regressions.
These tests do not validate the cryptographic correctness of the `openssl` package.

On top of that, the Microsoft CI built and tested a subset of the supported OpenSSL versions as part of the [Microsoft build of Go](https://github.com/microsoft/go) release process.
These tests were much more exhaustive and validated that a specific OpenSSL version can produce working applications.
Only OpenSSL 1.1.1 went through this process.

> [!NOTE]
> This module is not used by any active branches of the Microsoft build of Go, so those Microsoft CI tests no longer run.
> Active branches use and test [golang-fips/openssl](https://github.com/golang-fips/openssl).

Versions not listed above are not supported by this module.

Due to the stronger API stability promises of OpenSSL 3.x, this module may work with untested 3.x versions.

### Dynamic OpenSSL loading

The OpenSSL shared library `libcrypto` is loaded at runtime using [dlopen](https://man7.org/linux/man-pages/man3/dlopen.3.html) when calling `openssl.Init`. Therefore, dlopen's shared library search conventions also apply here.

The `libcrypto` shared library file name varies among different platforms, so a best effort is done to find and load the right file:

- The base name is always `libcrypto.so`.
- Well-known version strings are appended to the base name, until the file is found, in the following order: `3` -> `1.1` -> `11` -> `111` -> `1.0.2` -> `1.0.0`.

This algorithm can be overridden by setting the environment variable `GO_OPENSSL_VERSION_OVERRIDE` to the desired version string. For example, `GO_OPENSSL_VERSION_OVERRIDE="1.1.1k-fips"` makes the runtime look for the shared library `libcrypto.so.1.1.1k-fips` before running the checks for well-known versions.

### Building without OpenSSL headers

The `openssl` package does not use any symbol from the OpenSSL headers. There is no need that have them installed to build an application which imports this library.

Microsoft CI verifies that all the functions and constants defined in our headers match the ones in the OpenSSL headers for every supported OpenSSL version.

### Portable OpenSSL

The OpenSSL bindings are implemented in such a way that the OpenSSL version used when building a program does not have to match with the OpenSSL version used when running it.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain.

## Limitations

OpenSSL is used for a given build only in limited circumstances:

- The platform must be GOOS=linux.
- The build must have cgo enabled.
- The android build tag must not be specified.

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- All crypto stubs are a mirror of Google's [dev.boringcrypto branch](https://github.com/golang/go/tree/dev.boringcrypto) and the release branch ports of that branch.
- The mapping between BoringSSL and OpenSSL APIs is taken from Fedora's [Go fork](https://pagure.io/go).
- The portable OpenSSL implementation is ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
