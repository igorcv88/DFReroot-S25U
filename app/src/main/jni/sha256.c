/* sha256.c - see sha256.h. Compact, portable SHA-256. */
#include "sha256.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x)  (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(dfr_sha256_ctx *c, const uint8_t data[64]) {
    uint32_t a,b,cc,d,e,f,g,h,t1,t2,mm[64];
    int i, j;
    for (i = 0, j = 0; i < 16; i++, j += 4)
        mm[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | data[j+3];
    for (; i < 64; i++)
        mm[i] = SIG1(mm[i-2]) + mm[i-7] + SIG0(mm[i-15]) + mm[i-16];
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + mm[i];
        t2 = EP0(a) + MAJ(a,b,cc);
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void dfr_sha256_init(dfr_sha256_ctx *c) {
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85; c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c; c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}

void dfr_sha256_update(dfr_sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t i;
    for (i = 0; i < len; i++) {
        c->data[c->datalen++] = p[i];
        if (c->datalen == 64) {
            sha256_transform(c, c->data);
            c->bitlen += 512;
            c->datalen = 0;
        }
    }
}

void dfr_sha256_final(dfr_sha256_ctx *c, uint8_t out[32]) {
    size_t i = c->datalen;
    c->data[i++] = 0x80;
    if (c->datalen < 56) {
        while (i < 56) c->data[i++] = 0;
    } else {
        while (i < 64) c->data[i++] = 0;
        sha256_transform(c, c->data);
        memset(c->data, 0, 56);
    }
    c->bitlen += (uint64_t)c->datalen * 8;
    for (int k = 0; k < 8; k++)
        c->data[63-k] = (uint8_t)(c->bitlen >> (8*k));
    sha256_transform(c, c->data);
    for (i = 0; i < 4; i++)
        for (int k = 0; k < 8; k++)
            out[i + 4*k] = (uint8_t)(c->state[k] >> (24 - i*8));
}

void dfr_sha256_hex(const uint8_t digest[32], char hexout[65]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hexout[i*2]   = hx[(digest[i] >> 4) & 0xf];
        hexout[i*2+1] = hx[digest[i] & 0xf];
    }
    hexout[64] = 0;
}

int dfr_sha256_file_hex(const char *path, char hexout[65]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    dfr_sha256_ctx c;
    dfr_sha256_init(&c);
    uint8_t buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        dfr_sha256_update(&c, buf, (size_t)n);
    close(fd);
    if (n < 0) return -1;
    uint8_t digest[32];
    dfr_sha256_final(&c, digest);
    dfr_sha256_hex(digest, hexout);
    return 0;
}
