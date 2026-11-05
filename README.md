# Go OpenSSL bindings for FIPS compliance

[![Go Reference](https://pkg.go.dev/badge/github.com/microsoft/go-crypto-openssl/openssl.svg)](https://pkg.go.dev/github.com/microsoft/go-crypto-openssl/openssl)

The `openssl` package implements Go crypto primitives using OpenSSL shared libraries and cgo. When configured correctly, OpenSSL can be executed in FIPS mode, making the `openssl` package FIPS compliant.

The `openssl` package is designed to be used as a drop-in replacement for the [boring](https://pkg.go.dev/crypto/internal/boring) package in order to facilitate integrating `openssl` inside a forked Go toolchain.

Visit the [FIPS documentation in the microsoft/go repository](https://github.com/microsoft/go/tree/microsoft/main/eng/doc/fips) for more information about FIPS, enabling FIPS mode, and writing a FIPS compliant Go application.

## Disclaimer

A program directly or indirectly using this package in FIPS mode can claim it is using a FIPS-certified cryptographic module (OpenSSL), but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

## Features

### Multiple OpenSSL versions supported

The `openssl` package has support for multiple OpenSSL versions, namely 1.1.1, 3.x, and 4.x.

All supported OpenSSL versions pass a small set of automatic tests that ensure they can be built and that there are no major regressions.
These tests do not validate the cryptographic correctness of the `openssl` package.

On top of that, the [Microsoft build of Go](https://github.com/microsoft/go) tests a subset of the supported OpenSSL versions when integrated with the Go `crypto` package.
These tests are much more exhaustive and validate a specific OpenSSL version can produce working applications.

### Building without OpenSSL headers

The `openssl` package does not use any symbol from the OpenSSL headers. There is no need to have them installed to build an application which imports this library.

The CI tests in this repository verify that all the functions and constants defined in our headers match the ones in the OpenSSL headers for every supported OpenSSL version.

### Portable OpenSSL

The OpenSSL bindings are implemented in such a way that the OpenSSL version available when building a program does not have to match with the OpenSSL version used when running it.
In fact, OpenSSL doesn't need to be present on the builder.
For example, using the `openssl` package and `go build .` on a Windows host with `GOOS=linux` can produce a program that successfully runs on Linux and uses OpenSSL.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain that integrates the `openssl` package.

## Limitations

- Only Unix, Unix-like and Windows platforms are supported.

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- All crypto stubs are a mirror of Google's [dev.boringcrypto branch](https://github.com/golang/go/tree/dev.boringcrypto) and the release branch ports of that branch.
- The mapping between BoringSSL and OpenSSL APIs is taken from the former [Red Hat Go fork](https://pagure.io/go).
- The portable OpenSSL implementation is ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Code of Conduct

This project adopts the Go code of conduct: https://go.dev/conduct.
