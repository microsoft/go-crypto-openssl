// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// fakelibcrypto is a stub libcrypto used to exercise the library rejection
// paths in openLibrary. It never exports BN_bn2lebinpad.
//
// Without FAKE_VERSION_NUM it exports no version function at all. With it,
// it exports OpenSSL_version_num returning that value, like OpenSSL 1.x and
// forks such as AWS-LC (0x1010107f) and BoringSSL.

#ifdef FAKE_VERSION_NUM
unsigned long OpenSSL_version_num(void) { return FAKE_VERSION_NUM; }

const char *OpenSSL_version(int t) { (void)t; return "fakelibcrypto"; }
#else
int fakelibcrypto_unused;
#endif
