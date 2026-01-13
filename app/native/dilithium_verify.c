#include <stdint.h>
#include <stddef.h>

#include "api.h"  // from PQClean ml-dsa-87/clean

// returns 1 = valid, 0 = invalid
int dna_verify_mldsa87(
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *pk,  size_t pk_len
) {
    if (pk_len != PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES) return 0;
    if (sig_len != PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES) return 0;

    // PQClean verify returns 0 on success
    int rc = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
    return (rc == 0) ? 1 : 0;
}
