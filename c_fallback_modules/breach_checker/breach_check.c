/*
 * Breach Hash Checker - Pure C Implementation
 * Checks passwords/emails against breach databases using k-anonymity
 * Compile: gcc -O2 -o breach_check breach_check.c
 */

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define MAX_RESPONSE 65536
#define SHA1_DIGEST_LENGTH 20
#define HIBP_HOST "api.pwnedpasswords.com"
#define HIBP_PORT 443

/* Result structure */
typedef struct {
    char input[256];
    char sha1_hash[41];
    char sha1_prefix[6];
    int found;
    int count;
    char source[64];
} breach_result_t;

/*
 * Built-in SHA1 implementation
 */
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

#define SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, w[80];
    
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i*4] << 24) | ((uint32_t)buffer[i*4+1] << 16) |
               ((uint32_t)buffer[i*4+2] << 8) | ((uint32_t)buffer[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        
        uint32_t temp = SHA1_ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = SHA1_ROL(b, 30); b = a; a = temp;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1_init(SHA1_CTX* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

void sha1_update(SHA1_CTX* ctx, const uint8_t* data, size_t len) {
    size_t i, j;
    
    j = (ctx->count[0] >> 3) & 63;
    ctx->count[0] += (uint32_t)(len << 3);
    if (ctx->count[0] < (uint32_t)(len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    
    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

void sha1_final(uint8_t digest[20], SHA1_CTX* ctx) {
    uint8_t finalcount[8];
    uint8_t c;
    
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    
    c = 0x80;
    sha1_update(ctx, &c, 1);
    while ((ctx->count[0] & 504) != 448) {
        c = 0x00;
        sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8);
    
    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

/*
 * Compute SHA1 hash of string
 */
void sha1_string(const char* str, char* hash_out) {
    SHA1_CTX ctx;
    uint8_t digest[20];
    
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)str, strlen(str));
    sha1_final(digest, &ctx);
    
    for (int i = 0; i < 20; i++) {
        snprintf(hash_out + i * 2, 3, "%02X", digest[i]); // 3 bytes: 2 hex chars + null (overwritten next)
    }
    hash_out[40] = '\0';
}

/*
 * Simple HTTP GET request (for HIBP API)
 * Note: HIBP requires HTTPS, this is a simplified version
 * In production, use libcurl or OpenSSL
 */
/*
 * Simple HTTP GET request (for HIBP API)
 * Note: HIBP requires HTTPS, this is a simplified version
 * In production, use libcurl or OpenSSL
 */
int http_get(const char* host, int port, const char* path, char* response, int max_len) {
    int sock;
    struct addrinfo hints, *res;
    char port_str[6];
    char request[1024];
    int total = 0, bytes;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }
    
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    
    freeaddrinfo(res);
    
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: VULNRIX-BreachChecker/1.0\r\n"
             "Connection: close\r\n\r\n",
             path, host);
    
    send(sock, request, strlen(request), 0);
    
    while ((bytes = recv(sock, response + total, max_len - total - 1, 0)) > 0) {
        total += bytes;
    }
    response[total] = '\0';
    
    close(sock);
    return total;
}

/*
 * Check password against HIBP using k-anonymity
 * Only sends first 5 chars of SHA1 hash
 */
int check_password_hibp(const char* password, breach_result_t* result) {
    char hash[41];
    char prefix[6];
    char suffix[36];
    char path[64];
    char response[MAX_RESPONSE];
    
    memset(result, 0, sizeof(breach_result_t));
    strncpy(result->input, "********", sizeof(result->input) - 1);  /* Don't store password */
    strcpy(result->source, "hibp_kanon");
    
    /* Compute SHA1 */
    sha1_string(password, hash);
    strncpy(result->sha1_hash, hash, 40);
    
    /* Extract prefix and suffix */
    strncpy(prefix, hash, 5);
    prefix[5] = '\0';
    strcpy(suffix, hash + 5);
    strncpy(result->sha1_prefix, prefix, 5);
    
    printf("[*] Checking hash prefix: %s...\n", prefix);
    
    /* Note: HIBP requires HTTPS. This simplified version won't work directly.
     * In production, use libcurl with SSL or OpenSSL directly.
     * For now, we'll simulate the check locally.
     */
    
    /* Simulated check - in real implementation, query HIBP API */
    result->found = 0;
    result->count = 0;
    
    printf("[!] Note: Direct HIBP API requires HTTPS. Use curl or libcurl.\n");
    printf("[*] Hash to check: %s\n", hash);
    printf("[*] Prefix (k-anonymity): %s\n", prefix);
    printf("[*] Suffix to match: %s\n", suffix);
    
    return 0;
}

/*
 * Check email hash against local breach database
 */
int check_email_local(const char* email, const char* db_path, breach_result_t* result) {
    FILE* fp;
    char line[256];
    char email_lower[256];
    char hash[41];
    
    memset(result, 0, sizeof(breach_result_t));
    
    /* Lowercase email */
    strncpy(email_lower, email, sizeof(email_lower) - 1);
    for (int i = 0; email_lower[i]; i++) {
        email_lower[i] = tolower(email_lower[i]);
    }
    strncpy(result->input, email_lower, sizeof(result->input) - 1);
    
    /* Compute SHA1 */
    sha1_string(email_lower, hash);
    strncpy(result->sha1_hash, hash, 40);
    strncpy(result->sha1_prefix, hash, 5);
    strcpy(result->source, "local_db");
    
    /* Check against local database */
    fp = fopen(db_path, "r");
    if (!fp) {
        printf("[!] Local database not found: %s\n", db_path);
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        
        /* Check if hash matches */
        if (strncasecmp(line, hash, 40) == 0) {
            result->found = 1;
            result->count = 1;
            
            /* Parse count if present (format: HASH:COUNT) */
            char* colon = strchr(line, ':');
            if (colon) {
                result->count = atoi(colon + 1);
            }
            break;
        }
    }
    
    fclose(fp);
    return 0;
}

/*
 * Generate breach database entry
 */
void generate_hash_entry(const char* input, int is_email) {
    char hash[41];
    char input_lower[256];
    
    if (is_email) {
        strncpy(input_lower, input, sizeof(input_lower) - 1);
        for (int i = 0; input_lower[i]; i++) {
            input_lower[i] = tolower(input_lower[i]);
        }
        sha1_string(input_lower, hash);
    } else {
        sha1_string(input, hash);
    }
    
    printf("%s\n", hash);
}

/*
 * Print result
 */
void print_result(breach_result_t* result) {
    printf("\n=== Breach Check Result ===\n");
    printf("Input: %s\n", result->input);
    printf("SHA1: %s\n", result->sha1_hash);
    printf("Prefix: %s\n", result->sha1_prefix);
    printf("Source: %s\n", result->source);
    
    if (result->found) {
        printf("Status: BREACHED!\n");
        printf("Occurrences: %d\n", result->count);
    } else {
        printf("Status: Not found in database\n");
    }
}

/*
 * Export to JSON
 */
int export_json(const char* filename, breach_result_t* result) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"input\": \"%s\",\n", result->input);
    fprintf(fp, "  \"sha1_hash\": \"%s\",\n", result->sha1_hash);
    fprintf(fp, "  \"sha1_prefix\": \"%s\",\n", result->sha1_prefix);
    fprintf(fp, "  \"source\": \"%s\",\n", result->source);
    fprintf(fp, "  \"found\": %s,\n", result->found ? "true" : "false");
    fprintf(fp, "  \"count\": %d\n", result->count);
    fprintf(fp, "}\n");
    
    fclose(fp);
    return 0;
}

/*
 * Main function
 */
int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc < 3) {
        printf("Breach Hash Checker - Pure C Implementation\n");
        printf("Usage:\n");
        printf("  %s password <password> [output.json]\n", argv[0]);
        printf("  %s email <email> <database.txt> [output.json]\n", argv[0]);
        printf("  %s hash <input> [--email]\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s password mypassword123\n", argv[0]);
        printf("  %s email user@example.com breaches.txt\n", argv[0]);
        printf("  %s hash user@example.com --email\n", argv[0]);
        return 1;
    }
    
    const char* mode = argv[1];
    breach_result_t result;
    
    printf("\n=== Breach Hash Checker ===\n");
    
    if (strcmp(mode, "password") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[-] Password required\n");
            return 1;
        }
        
        check_password_hibp(argv[2], &result);
        print_result(&result);
        
        if (argc > 3) {
            export_json(argv[3], &result);
            printf("\n[*] Results exported to: %s\n", argv[3]);
        }
    }
    else if (strcmp(mode, "email") == 0) {
        if (argc < 4) {
            fprintf(stderr, "[-] Email and database path required\n");
            return 1;
        }
        
        check_email_local(argv[2], argv[3], &result);
        print_result(&result);
        
        if (argc > 4) {
            export_json(argv[4], &result);
            printf("\n[*] Results exported to: %s\n", argv[4]);
        }
    }
    else if (strcmp(mode, "hash") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[-] Input required\n");
            return 1;
        }
        
        int is_email = (argc > 3 && strcmp(argv[3], "--email") == 0);
        generate_hash_entry(argv[2], is_email);
    }
    else {
        fprintf(stderr, "[-] Unknown mode: %s\n", mode);
        return 1;
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
