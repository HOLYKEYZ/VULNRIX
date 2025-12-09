/*
 * DNS Scanner - Pure C Implementation
 * Subdomain enumeration using DNS resolution
 * Compile: gcc -O2 -pthread -o dns_scan dns_scan.c
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
#include <pthread.h>
#include <time.h>

#define MAX_SUBDOMAIN_LEN 256
#define MAX_IP_LEN 46
#define MAX_RESULTS 10000
#define MAX_WORDLIST 50000

/* Result structure */
typedef struct {
    char subdomain[MAX_SUBDOMAIN_LEN];
    char ip[MAX_IP_LEN];
    int found;
} dns_result_t;

/* Thread arguments */
typedef struct {
    char** wordlist;
    int start_idx;
    int end_idx;
    const char* base_domain;
    dns_result_t* results;
    int* result_count;
    pthread_mutex_t* mutex;
} thread_args_t;

/* Global stats */
static int total_checked = 0;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Check if subdomain resolves to an IP
 * Returns 1 if found, 0 otherwise
 */
int check_subdomain(const char* subdomain, char* ip_out) {
    struct addrinfo hints, *res, *p;
    int status;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    status = getaddrinfo(subdomain, NULL, &hints, &res);
    if (status != 0) {
        return 0;
    }
    
    for (p = res; p != NULL; p = p->ai_next) {
        void* addr;
        
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        
        inet_ntop(p->ai_family, addr, ip_out, MAX_IP_LEN);
        freeaddrinfo(res);
        return 1;
    }
    
    freeaddrinfo(res);
    return 0;
}

/*
 * Worker thread function for parallel scanning
 */
void* scan_worker(void* args) {
    thread_args_t* targs = (thread_args_t*)args;
    char subdomain[512];
    char ip[MAX_IP_LEN];
    
    for (int i = targs->start_idx; i < targs->end_idx; i++) {
        snprintf(subdomain, sizeof(subdomain), "%s.%s",
                 targs->wordlist[i], targs->base_domain);
        
        /* Update stats */
        pthread_mutex_lock(&stats_mutex);
        total_checked++;
        pthread_mutex_unlock(&stats_mutex);
        
        if (check_subdomain(subdomain, ip)) {
            pthread_mutex_lock(targs->mutex);
            
            if (*targs->result_count < MAX_RESULTS) {
                int idx = *targs->result_count;
                strncpy(targs->results[idx].subdomain, 
                        subdomain, MAX_SUBDOMAIN_LEN - 1);
                targs->results[idx].subdomain[MAX_SUBDOMAIN_LEN - 1] = '\0';
                strncpy(targs->results[idx].ip, 
                        ip, MAX_IP_LEN - 1);
                targs->results[idx].ip[MAX_IP_LEN - 1] = '\0';
                targs->results[idx].found = 1;
                (*targs->result_count)++;
                
                printf("[+] Found: %s -> %s\n", subdomain, ip);
            }
            
            pthread_mutex_unlock(targs->mutex);
        }
    }
    
    return NULL;
}

/*
 * Load wordlist from file
 * Returns number of words loaded
 */
int load_wordlist(const char* path, char*** wordlist_out) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[-] Failed to open wordlist: %s\n", path);
        return -1;
    }
    
    char** wordlist = malloc(sizeof(char*) * MAX_WORDLIST);
    if (!wordlist) {
        fclose(fp);
        return -1;
    }
    
    int count = 0;
    char line[256];
    
    while (fgets(line, sizeof(line), fp) && count < MAX_WORDLIST) {
        /* Remove newline */
        line[strcspn(line, "\r\n")] = 0;
        
        /* Skip empty lines */
        if (strlen(line) == 0) continue;
        
        wordlist[count] = strdup(line);
        if (wordlist[count]) {
            count++;
        }
    }
    
    fclose(fp);
    *wordlist_out = wordlist;
    return count;
}

/*
 * Free wordlist memory
 */
void free_wordlist(char** wordlist, int count) {
    for (int i = 0; i < count; i++) {
        free(wordlist[i]);
    }
    free(wordlist);
}

/*
 * Main enumeration function
 * Returns number of subdomains found, -1 on error
 */
int enumerate_subdomains(const char* domain, const char* wordlist_path,
                         int num_threads, dns_result_t** results_out) {
    char** wordlist;
    int word_count;
    
    printf("[*] Loading wordlist: %s\n", wordlist_path);
    word_count = load_wordlist(wordlist_path, &wordlist);
    if (word_count < 0) {
        return -1;
    }
    printf("[*] Loaded %d words\n", word_count);
    
    /* Allocate results */
    dns_result_t* results = calloc(MAX_RESULTS, sizeof(dns_result_t));
    if (!results) {
        free_wordlist(wordlist, word_count);
        return -1;
    }
    
    int result_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    total_checked = 0;
    
    /* Create threads */
    pthread_t* threads = malloc(sizeof(pthread_t) * num_threads);
    thread_args_t* thread_args = malloc(sizeof(thread_args_t) * num_threads);
    
    if (!threads || !thread_args) {
        free(results);
        free_wordlist(wordlist, word_count);
        if (threads) free(threads);
        if (thread_args) free(thread_args);
        return -1;
    }
    
    int chunk_size = word_count / num_threads;
    
    printf("[*] Starting %d threads...\n", num_threads);
    clock_t start = clock();
    
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].wordlist = wordlist;
        thread_args[i].start_idx = i * chunk_size;
        thread_args[i].end_idx = (i == num_threads - 1) ? word_count : (i + 1) * chunk_size;
        thread_args[i].base_domain = domain;
        thread_args[i].results = results;
        thread_args[i].result_count = &result_count;
        thread_args[i].mutex = &mutex;
        
        pthread_create(&threads[i], NULL, scan_worker, &thread_args[i]);
    }
    
    /* Wait for completion */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_t end = clock();
    double duration = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("[*] Scan completed in %.2f seconds\n", duration);
    printf("[*] Checked %d subdomains, found %d\n", total_checked, result_count);
    
    /* Cleanup */
    free_wordlist(wordlist, word_count);
    free(threads);
    free(thread_args);
    pthread_mutex_destroy(&mutex);
    
    *results_out = results;
    return result_count;
}

/*
 * Export results to JSON file
 */
int export_json(const char* filename, dns_result_t* results, int count) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n  \"subdomains\": [\n");
    
    for (int i = 0; i < count; i++) {
        fprintf(fp, "    {\"subdomain\": \"%s\", \"ip\": \"%s\"}%s\n",
                results[i].subdomain, results[i].ip,
                (i < count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ],\n  \"total\": %d\n}\n", count);
    fclose(fp);
    return 0;
}

/*
 * Main function for standalone execution
 */
int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc < 3) {
        printf("DNS Subdomain Scanner - Pure C Implementation\n");
        printf("Usage: %s <domain> <wordlist> [threads] [output.json]\n", argv[0]);
        printf("Example: %s example.com wordlist.txt 20 results.json\n", argv[0]);
        return 1;
    }
    
    const char* domain = argv[1];
    const char* wordlist = argv[2];
    int threads = (argc > 3) ? atoi(argv[3]) : 10;
    const char* output = (argc > 4) ? argv[4] : NULL;
    
    if (threads < 1) threads = 1;
    if (threads > 100) threads = 100;
    
    printf("\n=== DNS Subdomain Scanner ===\n");
    printf("[*] Target: %s\n", domain);
    printf("[*] Wordlist: %s\n", wordlist);
    printf("[*] Threads: %d\n\n", threads);
    
    dns_result_t* results;
    int count = enumerate_subdomains(domain, wordlist, threads, &results);
    
    if (count < 0) {
        fprintf(stderr, "[-] Scan failed\n");
        return 1;
    }
    
    /* Print summary */
    printf("\n=== Results ===\n");
    for (int i = 0; i < count; i++) {
        printf("%s -> %s\n", results[i].subdomain, results[i].ip);
    }
    
    /* Export if output file specified */
    if (output) {
        if (export_json(output, results, count) == 0) {
            printf("\n[*] Results exported to: %s\n", output);
        }
    }
    
    free(results);
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
