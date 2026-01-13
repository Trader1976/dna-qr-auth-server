// app/native/dilithium_verify.c
// Native verifier wrapper for PQClean ML-DSA-87 (Dilithium5-class signature)
//
// Exposes:
//   int dna_verify_mldsa87(const uint8_t* msg, size_t msg_len,
//                          const uint8_t* sig, size_t sig_len,
//                          const uint8_t* pk,  size_t pk_len);
//
// Returns 1 on success, 0 on failure.

#include <stdint.h>
#include <stddef.h>

// We compile with -I .../crypto_sign/ml-dsa-87/clean so "api.h" resolves.
#include "api.h"

// PQClean uses algorithm-specific symbol prefixes in api.h.
// For ML-DSA-87 clean, the verify symbol is typically:
//   PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk)
//
// If your api.h uses a different exact name, run:
//   grep -R "crypto_sign_verify" -n app/native/PQClean/crypto_sign/ml-dsa-87/clean/api.h

int dna_verify_mldsa87(const uint8_t* msg, size_t msg_len,
                       const uint8_t* sig, size_t sig_len,
                       const uint8_t* pk,  size_t pk_len) {
    (void)pk_len; // PQClean verify does not require pk_len (fixed-size key)

    // Return 1 if signature verifies, else 0
    int rc = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
    return (rc == 0) ? 1 : 0;
}
