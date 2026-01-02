/*
 * File Hash Computer - Pure C Implementation
 * Computes MD5, SHA1, SHA256 hashes
 * Compile: gcc -O2 -o file_hash file_hash.c -lcrypto
 * Or without OpenSSL: gcc -O2 -DUSE_BUILTIN -o file_hash file_hash.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "advapi32.lib")
#endif

#define BUFFER_SIZE 65536
#define MD5_DIGEST_LENGTH 16
#define SHA1_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32

/* Hash result structure */
typedef struct {
    char filename[1024];
    uint64_t file_size;
    char md5[33];
    char sha1[41];
    char sha256[65];
    double compute_time;
} hash_result_t;

/*
 * Built-in MD5 implementation (no external dependencies)
 */
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} MD5_CTX;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j+1]) << 8) |
               (((uint32_t)block[j+2]) << 16) | (((uint32_t)block[j+3]) << 24);
    }
    
    /* Round 1 */
    FF(a, b, c, d, x[ 0],  7, 0xd76aa478);
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], 17, 0x242070db);
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[ 4],  7, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], 17, 0xa8304613);
    FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    FF(a, b, c, d, x[ 8],  7, 0x698098d8);
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12],  7, 0x6b901122);
    FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e);
    FF(b, c, d, a, x[15], 22, 0x49b40821);
    
    /* Round 2 */
    GG(a, b, c, d, x[ 1],  5, 0xf61e2562);
    GG(d, a, b, c, x[ 6],  9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51);
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5],  5, 0xd62f105d);
    GG(d, a, b, c, x[10],  9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9],  5, 0x21e1cde6);
    GG(d, a, b, c, x[14],  9, 0xc33707d6);
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13],  5, 0xa9e3e905);
    GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9);
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
    
    /* Round 3 */
    HH(a, b, c, d, x[ 5],  4, 0xfffa3942);
    HH(d, a, b, c, x[ 8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[ 1],  4, 0xa4beea44);
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13],  4, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], 23, 0x04881d05);
    HH(a, b, c, d, x[ 9],  4, 0xd9d4d039);
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);
    
    /* Round 4 */
    II(a, b, c, d, x[ 0],  6, 0xf4292244);
    II(d, a, b, c, x[ 7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7);
    II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    II(a, b, c, d, x[12],  6, 0x655b59c3);
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d);
    II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    II(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], 15, 0xa3014314);
    II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[ 4],  6, 0xf7537e82);
    II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], 21, 0xeb86d391);
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md5_init(MD5_CTX* ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

void md5_update(MD5_CTX* ctx, const uint8_t* input, size_t len) {
    size_t i, index, part_len;
    
    index = (ctx->count[0] >> 3) & 0x3F;
    ctx->count[0] += (uint32_t)(len << 3);
    if (ctx->count[0] < (uint32_t)(len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    
    part_len = 64 - index;
    
    if (len >= part_len) {
        memcpy(&ctx->buffer[index], input, part_len);
        md5_transform(ctx->state, ctx->buffer);
        
        for (i = part_len; i + 63 < len; i += 64) {
            md5_transform(ctx->state, &input[i]);
        }
        index = 0;
    } else {
        i = 0;
    }
    
    memcpy(&ctx->buffer[index], &input[i], len - i);
}

void md5_final(uint8_t digest[16], MD5_CTX* ctx) {
    static uint8_t padding[64] = { 0x80 };
    uint8_t bits[8];
    size_t index, pad_len;
    
    for (int i = 0; i < 4; i++) {
        bits[i] = (ctx->count[0] >> (i * 8)) & 0xff;
        bits[i + 4] = (ctx->count[1] >> (i * 8)) & 0xff;
    }
    
    index = (ctx->count[0] >> 3) & 0x3f;
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, padding, pad_len);
    md5_update(ctx, bits, 8);
    
    for (int i = 0; i < 4; i++) {
        digest[i] = (ctx->state[0] >> (i * 8)) & 0xff;
        digest[i + 4] = (ctx->state[1] >> (i * 8)) & 0xff;
        digest[i + 8] = (ctx->state[2] >> (i * 8)) & 0xff;
        digest[i + 12] = (ctx->state[3] >> (i * 8)) & 0xff;
    }
}

/*
 * Built-in SHA256 implementation
 */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} SHA256_CTX;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX* ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }
    
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX* ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

void sha256_final(uint8_t hash[32], SHA256_CTX* ctx) {
    uint64_t bits = ctx->count * 8;
    size_t pad_len = (ctx->count % 64 < 56) ? (56 - ctx->count % 64) : (120 - ctx->count % 64);
    
    uint8_t padding[64] = {0x80};
    sha256_update(ctx, padding, 1);
    
    uint8_t zeros[64] = {0};
    sha256_update(ctx, zeros, pad_len - 1);
    
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++) {
        len_bytes[7 - i] = (bits >> (i * 8)) & 0xff;
    }
    sha256_update(ctx, len_bytes, 8);
    
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (ctx->state[i] >> 24) & 0xff;
        hash[i*4+1] = (ctx->state[i] >> 16) & 0xff;
        hash[i*4+2] = (ctx->state[i] >> 8) & 0xff;
        hash[i*4+3] = ctx->state[i] & 0xff;
    }
}

/*
 * Convert bytes to hex string
 */
void bytes_to_hex(const uint8_t* bytes, int len, char* hex) {
    for (int i = 0; i < len; i++) {
        snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

/*
 * Compute all hashes for a file
 */
int compute_file_hashes(const char* filename, hash_result_t* result) {
    FILE* fp;
    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;
    clock_t start, end;
    
    MD5_CTX md5_ctx;
    SHA256_CTX sha256_ctx;
    uint8_t md5_digest[16];
    uint8_t sha256_digest[32];
    
    memset(result, 0, sizeof(hash_result_t));
    strncpy(result->filename, filename, sizeof(result->filename) - 1);
    result->filename[sizeof(result->filename) - 1] = '\0'; // Ensure NULL
    
    fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "[-] Failed to open file: %s\n", filename);
        return -1;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    result->file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    start = clock();
    
    /* Initialize contexts */
    md5_init(&md5_ctx);
    sha256_init(&sha256_ctx);
    
    /* Read and hash */
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        md5_update(&md5_ctx, buffer, bytes_read);
        sha256_update(&sha256_ctx, buffer, bytes_read);
    }
    
    fclose(fp);
    
    /* Finalize */
    md5_final(md5_digest, &md5_ctx);
    sha256_final(sha256_digest, &sha256_ctx);
    
    end = clock();
    result->compute_time = (double)(end - start) / CLOCKS_PER_SEC;
    
    /* Convert to hex */
    bytes_to_hex(md5_digest, 16, result->md5);
    bytes_to_hex(sha256_digest, 32, result->sha256);
    
    /* SHA1 placeholder - would need full implementation */
    strcpy(result->sha1, "not_implemented");
    
    return 0;
}

/*
 * Print result
 */
void print_result(hash_result_t* result) {
    printf("\n=== File Hash Result ===\n");
    printf("File: %s\n", result->filename);
    printf("Size: %llu bytes\n", (unsigned long long)result->file_size);
    printf("MD5:    %s\n", result->md5);
    printf("SHA256: %s\n", result->sha256);
    printf("Time: %.3f seconds\n", result->compute_time);
}

/*
 * Export to JSON
 */
int export_json(const char* filename, hash_result_t* result) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"filename\": \"%s\",\n", result->filename);
    fprintf(fp, "  \"file_size\": %llu,\n", (unsigned long long)result->file_size);
    fprintf(fp, "  \"md5\": \"%s\",\n", result->md5);
    fprintf(fp, "  \"sha256\": \"%s\",\n", result->sha256);
    fprintf(fp, "  \"compute_time\": %.3f\n", result->compute_time);
    fprintf(fp, "}\n");
    
    fclose(fp);
    return 0;
}

/*
 * Main function
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("File Hash Computer - Pure C Implementation\n");
        printf("Usage: %s <file> [output.json]\n", argv[0]);
        printf("Example: %s document.pdf hashes.json\n", argv[0]);
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output = (argc > 2) ? argv[2] : NULL;
    
    printf("\n=== File Hash Computer ===\n");
    printf("[*] Computing hashes for: %s\n", input_file);
    
    hash_result_t result;
    if (compute_file_hashes(input_file, &result) < 0) {
        return 1;
    }
    
    print_result(&result);
    
    if (output) {
        if (export_json(output, &result) == 0) {
            printf("\n[*] Results exported to: %s\n", output);
        }
    }
    
    return 0;
}
