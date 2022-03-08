# Compatibility of Go BoringCrypto and OpenSSL

## Goal

List implementation decisions taken to smooth out differences between Go BoringCrypto expectations and OpenSSL behavior.

## Background

Go BoringCrypto branch delegates core cryptographic algorithms to BoringSSL. Go does not support pluggable crypto backends, so in order to support BoringSSL, the BoringCrypto branch contains non-trivial modifications to several `crypto` packages. These modifications are not generic abstractions over crypto algorithms as they specifically target BoringSSL compatibility.

The BoringSSL library was forked from OpenSSL 1.0.2 beta, a version that `go-crypto-openssl`supports and that already makes heavy use of the EVP interface. This fact facilitates the translation from BoringSSL to OpenSSL functions. Yet, Go BoringCrypto implements some algorithms using functions that are either deprecated in newer -but supported by us- OpenSSL versions or directly non-existing.

In this situations were there is no direct mapping, we try to combine several OpenSSL functions so the security is not compromised, being the trade-off between speed and maintainability.

## Implementation decisions

### AES-GCM encryption in TLS mode

#### Background

AES-GCM with Additional Data (aka AEAD) is a symmetric block cipher whose text-book encryption inputs are:
- initialization vector (aka nonce or iv)
- plaintext
- additional authenticated data

And the outputs are:
- ciphertext
- authentication tag

Go abstracts this algorithm using the `Seal` method in the [cipher.AEAD](https://pkg.go.dev/crypto/cipher#AEAD) interface:

`Seal(dst, nonce, plaintext, additionalData []byte) []byte`

Where dst is just a backing memory buffer to reduce allocations and the returned byte slice is the ciphertext with the authentication tag appended.

When AES-GCM is used to encrypt a TLS payload (aka TLS mode), FIPS 140-2 IG A.5 ["Key/IV Pair Uniqueness * Requirements from SP 800-38D"](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), and the general security consensus, requires constructing the IV parameter deterministically by concatenating two fields:
- Fixed 4 bytes field which identifies the encryption context and is reused in different Seal operations using the same key.
- Explicit 8 bytes field which identifies the Seal operation within an encryption context. This field must not be reused in the same encryption context and should be set using a counter incremented in every Seal operation within an encryption context.

As it is implemented in BoringCrypto, Go TLS stack is the one responsible of constructing a valid uniq Key/IV pair, which is passed the `Seal` method (backed by BoringSSL or OpenSSL) with the expectation that the nonce is honored. 

#### BoringSSL

BoringSSL implements the AES-GCM TLS encryption using the [EVP_AEAD_CTX_seal](https://man.openbsd.org/EVP_AEAD_CTX_seal.3) on-shot function, which have a one-to-one mapping with Go's `Seal` method and also enforces that the provided nonce matches the FIPS 140-2 IG A.5 requirements. So BoringSSL honors Go's IV and at the same time ensures it is secure.

#### OpenSSL

OpenSSL does not provide the `EVP_AEAD_CTX_seal` function, so AES-GCM should be implemented using several several EVP_ENCRYPT* functions, as described in [here](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption). The problem with this recipe is that it does not enforce the additional TLS requirements, it just blindly uses whatever IV is passed.

This is because OpenSSL don't expect that recipe to be used for AES-GCM TLS encryption, but it provided instead a control parameter, EVP_CTRL_AEAD_TLS1_AAD, that when applied to an encryption context it makes it work in TLS-mode and completely change the encryption workflow (more details [here](https://beta.openssl.org/docs/manmaster/man3/EVP_CipherInit_ex.html#tlsivfixed-OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED-octet-string)).

The main difference is that the explicit IV field is no longer managed by the caller but by the OpenSSL encryption context, incrementing it on every Seal operation and applying some additional checks. This means that OpenSSL won't honor the IV constructed by Go, and therefore it will make Go send corrupted packaged to the wire.

#### Assumptions

1. Go constructs IVs that are FIPS 140-2 compliant. BoringCrypto also works under this assumption.

#### Options

1. Use OpenSSL AES-GCM in TLS mode, which means IV construction is secured inside OpenSSL context but Go expectations are not meet, therefore it requires the following changes to Go TLS stack:
  - In `go-crypto-openssl`, change `NewGCMTLS` to accept the 4 bytes fixed IV field.
  - In `crypto/tls`:
    - Define a new AEAD-like interface, i.e. `AEAD2`, whose `Seal` method does not accept an IV and returns a byte slice with iv+ciphertext+tag.
    - Construct the AES-GCM TLS cipher using the new method.
    - Don't generate an IV when the cipher implements the AEAD2 interface.
    - Use the AEAD2 interface if available when encrypting.
    - Test and validate the new path.

2. Use OpenSSL AES-GCM in non-TLS mode, which means Go constructs the IV and OpenSSL honors it, but then we miss some required security checks that we would have to implement ourselves, namely:
  - Enforce strictly monotonically increasing explicit nonces.
  - Enforce explicit nonce values to be less than 2^64 - 1.
  - Tets the new checks.

#### Resolution

We will implement option 2.

Reasoning:
- The additional security checks are easy to implement.
- The changes are contained in `go-crypto-openssl`.
- Option 1 would require non-trivial patching of the Go TLS stack, which we would need to keep up-to-date when `crypto/tls` changes.
- Option 1 has higher chances to introduce a behavior chance or a security bug.

Drawbacks:
- OpenSSL might implement additional IV checks in future versions when running in TLS mode, and we will not benefit from them. We will have to keep an eye out for changes in this area.
- We will implement security checks that go outside the ideal scope of `go-crypto-openssl`, which is just to act at as a thin layer between Go and OpenSSL APIs without real security knowledge.

