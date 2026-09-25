/*
 * sha256.h - minimal, dependency-free SHA-256 (public-domain style).
 * Used by Gate B runtime userspace-identity validation in exp.c and by the
 * host tests. Not performance critical.
 */
#ifndef DFR_SHA256_H
#define DFR_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} dfr_sha256_ctx;

void dfr_sha256_init(dfr_sha256_ctx *c);
void dfr_sha256_update(dfr_sha256_ctx *c, const void *data, size_t len);
void dfr_sha256_final(dfr_sha256_ctx *c, uint8_t out[32]);

/* Convenience: hash a file, write lowercase hex (65 bytes incl NUL) to hexout.
 * Returns 0 on success, -1 if the file cannot be read. */
int dfr_sha256_file_hex(const char *path, char hexout[65]);

/* Format a 32-byte digest into 64 lowercase hex chars + NUL. */
void dfr_sha256_hex(const uint8_t digest[32], char hexout[65]);

#ifdef __cplusplus
}
#endif

#endif /* DFR_SHA256_H */
