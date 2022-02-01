// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2021 Google LLC
 */

#include <openssl/err.h>
#include <log.h>

// Array copied from src/crypto/err/err.c
static const char *const kLibraryNames[ERR_NUM_LIBS] = {
    "invalid library (0)",
    "unknown library",              // ERR_LIB_NONE
    "system library",               // ERR_LIB_SYS
    "bignum routines",              // ERR_LIB_BN
    "RSA routines",                 // ERR_LIB_RSA
    "Diffie-Hellman routines",      // ERR_LIB_DH
    "public key routines",          // ERR_LIB_EVP
    "memory buffer routines",       // ERR_LIB_BUF
    "object identifier routines",   // ERR_LIB_OBJ
    "PEM routines",                 // ERR_LIB_PEM
    "DSA routines",                 // ERR_LIB_DSA
    "X.509 certificate routines",   // ERR_LIB_X509
    "ASN.1 encoding routines",      // ERR_LIB_ASN1
    "configuration file routines",  // ERR_LIB_CONF
    "common libcrypto routines",    // ERR_LIB_CRYPTO
    "elliptic curve routines",      // ERR_LIB_EC
    "SSL routines",                 // ERR_LIB_SSL
    "BIO routines",                 // ERR_LIB_BIO
    "PKCS7 routines",               // ERR_LIB_PKCS7
    "PKCS8 routines",               // ERR_LIB_PKCS8
    "X509 V3 routines",             // ERR_LIB_X509V3
    "random number generator",      // ERR_LIB_RAND
    "ENGINE routines",              // ERR_LIB_ENGINE
    "OCSP routines",                // ERR_LIB_OCSP
    "UI routines",                  // ERR_LIB_UI
    "COMP routines",                // ERR_LIB_COMP
    "ECDSA routines",               // ERR_LIB_ECDSA
    "ECDH routines",                // ERR_LIB_ECDH
    "HMAC routines",                // ERR_LIB_HMAC
    "Digest functions",             // ERR_LIB_DIGEST
    "Cipher functions",             // ERR_LIB_CIPHER
    "HKDF functions",               // ERR_LIB_HKDF
    "Trust Token functions",        // ERR_LIB_TRUST_TOKEN
    "User defined functions",       // ERR_LIB_USER
};

void ERR_put_error(int lib, int unused, int reason, const char *file,
                   unsigned line) {
  printf("BoringSSL:%s:%u: Library '%d' (\"%s\"): reason '%d'", file, line, lib,
         kLibraryNames[0 <= lib && lib < ERR_NUM_LIBS ? lib : 1], reason);
}
