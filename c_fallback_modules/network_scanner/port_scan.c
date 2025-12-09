/*
 * Port Scanner - Pure C Implementation
 * TCP connect scan with banner grabbing
 * Compile: gcc -O2 -pthread -o port_scan port_scan.c
 */

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    #define SHUT_RDWR SD_BOTH
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define MAX_PORTS 65536
#define MAX_BANNER_LEN 512
#define MAX_RESULTS 1000
#define CONNECT_TIMEOUT_MS 1000
#define BANNER_TIMEOUT_MS 500

/* Port state */
typedef enum {
    PORT_CLOSED = 0,
    PORT_OPEN = 1,
    PORT_FILTERED = 2
} port_state_t;

/* Port result structure */
typedef struct {
    int port;
    port_state_t state;
    char service[64];
    char banner[MAX_BANNER_LEN];
    int banner_len;
} port_result_t;

/* Thread arguments */
typedef struct {
    const char* target_ip;
    int* ports;
    int start_idx;
    int end_idx;
    int timeout_ms;
    port_result_t* results;
    int* result_count;
    pthread_mutex_t* mutex;
} thread_args_t;

/* Common port services */
typedef struct {
    int port;
    const char* service;
    const char* probe;
} service_info_t;

static service_info_t SERVICES[] = {
    {21, "ftp", NULL},
    {22, "ssh", NULL},
    {23, "telnet", NULL},
    {25, "smtp", "EHLO scanner\r\n"},
    {53, "dns", NULL},
    {80, "http", "HEAD / HTTP/1.0\r\n\r\n"},
    {110, "pop3", NULL},
    {111, "rpcbind", NULL},
    {135, "msrpc", NULL},
    {139, "netbios", NULL},
    {143, "imap", NULL},
    {443, "https", NULL},
    {445, "smb", NULL},
    {993, "imaps", NULL},
    {995, "pop3s", NULL},
    {1433, "mssql", NULL},
    {1521, "oracle", NULL},
    {3306, "mysql", NULL},
    {3389, "rdp", NULL},
    {5432, "postgresql", NULL},
    {5900, "vnc", NULL},
    {6379, "redis", "PING\r\n"},
    {8080, "http-proxy", "HEAD / HTTP/1.0\r\n\r\n"},
    {8443, "https-alt", NULL},
    {27017, "mongodb", NULL},
    {0, NULL, NULL}
};

/* Get service name for port */
const char* get_service_name(int port) {
    for (int i = 0; SERVICES[i].service != NULL; i++) {
        if (SERVICES[i].port == port) {
            return SERVICES[i].service;
        }
    }
    return "unknown";
}

/* Get probe for port */
const char* get_probe(int port) {
    for (int i = 0; SERVICES[i].service != NULL; i++) {
        if (SERVICES[i].port == port) {
            return SERVICES[i].probe;
        }
    }
    return "\r\n";
}

/* Set socket non-blocking */
int set_nonblocking(int sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* Set socket blocking */
int set_blocking(int sock) {
#ifdef _WIN32
    u_long mode = 0;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

/*
 * Connect with timeout
 * Returns: 1 = open, 0 = closed, -1 = filtered/timeout
 */
int connect_with_timeout(const char* ip, int port, int timeout_ms) {
    int sock;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;
    int result;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    set_nonblocking(sock);
    
    result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
#ifdef _WIN32
    if (result < 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
#else
    if (result < 0 && errno != EINPROGRESS) {
#endif
        close(sock);
        return 0;
    }
    
    if (result == 0) {
        close(sock);
        return 1;
    }
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    result = select(sock + 1, NULL, &fdset, NULL, &tv);
    
    if (result > 0) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        close(sock);
        return (so_error == 0) ? 1 : 0;
    }
    
    close(sock);
    return -1;  /* Timeout = filtered */
}

/*
 * Grab banner from open port
 */
int grab_banner(const char* ip, int port, char* banner, int banner_size, int timeout_ms) {
    int sock;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;
    const char* probe;
    int bytes_read;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    /* Connect with timeout */
    set_nonblocking(sock);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    if (select(sock + 1, NULL, &fdset, NULL, &tv) <= 0) {
        close(sock);
        return 0;
    }
    
    set_blocking(sock);
    
    /* Send probe */
    probe = get_probe(port);
    if (probe) {
        send(sock, probe, strlen(probe), 0);
    }
    
    /* Receive banner */
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 0;
    tv.tv_usec = timeout_ms * 1000;
    
    if (select(sock + 1, &fdset, NULL, NULL, &tv) > 0) {
        bytes_read = recv(sock, banner, banner_size - 1, 0);
        if (bytes_read > 0) {
            banner[bytes_read] = '\0';
            /* Clean up banner - remove non-printable chars */
            for (int i = 0; i < bytes_read; i++) {
                if (banner[i] < 32 && banner[i] != '\n' && banner[i] != '\r') {
                    banner[i] = '.';
                }
            }
            close(sock);
            return bytes_read;
        }
    }
    
    close(sock);
    return 0;
}

/*
 * Worker thread for parallel scanning
 */
void* scan_worker(void* args) {
    thread_args_t* targs = (thread_args_t*)args;
    char banner[MAX_BANNER_LEN];
    
    for (int i = targs->start_idx; i < targs->end_idx; i++) {
        int port = targs->ports[i];
        int result = connect_with_timeout(targs->target_ip, port, targs->timeout_ms);
        
        if (result == 1) {  /* Port is open */
            pthread_mutex_lock(targs->mutex);
            
            if (*targs->result_count < MAX_RESULTS) {
                port_result_t* pr = &targs->results[*targs->result_count];
                pr->port = port;
                pr->state = PORT_OPEN;
                strncpy(pr->service, get_service_name(port), sizeof(pr->service) - 1);
                
                /* Try to grab banner */
                memset(banner, 0, sizeof(banner));
                pr->banner_len = grab_banner(targs->target_ip, port, banner, 
                                             sizeof(banner), BANNER_TIMEOUT_MS);
                if (pr->banner_len > 0) {
                    strncpy(pr->banner, banner, MAX_BANNER_LEN - 1);
                }
                
                (*targs->result_count)++;
                printf("[+] %d/tcp open  %-15s %s\n", port, pr->service,
                       pr->banner_len > 0 ? "(banner)" : "");
            }
            
            pthread_mutex_unlock(targs->mutex);
        }
    }
    
    return NULL;
}

/*
 * Resolve hostname to IP
 */
int resolve_host(const char* hostname, char* ip_out, int ip_size) {
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        return -1;
    }
    
    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_out, ip_size);
    
    freeaddrinfo(res);
    return 0;
}

/*
 * Main scan function
 */
int scan_ports(const char* target, int* ports, int port_count,
               int num_threads, int timeout_ms, port_result_t** results_out) {
    char ip[64];
    
    /* Resolve target */
    if (resolve_host(target, ip, sizeof(ip)) < 0) {
        /* Maybe it's already an IP */
        strncpy(ip, target, sizeof(ip) - 1);
    }
    
    printf("[*] Scanning %s (%s)\n", target, ip);
    printf("[*] Ports: %d, Threads: %d, Timeout: %dms\n\n", 
           port_count, num_threads, timeout_ms);
    
    /* Allocate results */
    port_result_t* results = calloc(MAX_RESULTS, sizeof(port_result_t));
    if (!results) return -1;
    
    int result_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    /* Create threads */
    pthread_t* threads = malloc(sizeof(pthread_t) * num_threads);
    thread_args_t* thread_args = malloc(sizeof(thread_args_t) * num_threads);
    
    if (!threads || !thread_args) {
        free(results);
        if (threads) free(threads);
        if (thread_args) free(thread_args);
        return -1;
    }
    
    int chunk_size = port_count / num_threads;
    if (chunk_size < 1) chunk_size = 1;
    
    clock_t start = clock();
    
    int actual_threads = 0;
    for (int i = 0; i < num_threads && i * chunk_size < port_count; i++) {
        thread_args[i].target_ip = ip;
        thread_args[i].ports = ports;
        thread_args[i].start_idx = i * chunk_size;
        thread_args[i].end_idx = (i == num_threads - 1) ? port_count : (i + 1) * chunk_size;
        thread_args[i].timeout_ms = timeout_ms;
        thread_args[i].results = results;
        thread_args[i].result_count = &result_count;
        thread_args[i].mutex = &mutex;
        
        pthread_create(&threads[i], NULL, scan_worker, &thread_args[i]);
        actual_threads++;
    }
    
    /* Wait for completion */
    for (int i = 0; i < actual_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_t end = clock();
    double duration = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("\n[*] Scan completed in %.2f seconds\n", duration);
    printf("[*] %d ports scanned, %d open\n", port_count, result_count);
    
    /* Cleanup */
    free(threads);
    free(thread_args);
    pthread_mutex_destroy(&mutex);
    
    *results_out = results;
    return result_count;
}

/*
 * Generate port list
 */
int generate_port_list(const char* spec, int** ports_out) {
    int* ports = malloc(sizeof(int) * MAX_PORTS);
    int count = 0;
    
    if (strcmp(spec, "top100") == 0) {
        int top100[] = {21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                        1433,1521,3306,3389,5432,5900,6379,8080,8443,27017,
                        81,82,83,84,85,88,8000,8001,8008,8081,8082,8083,8084,
                        8085,8880,8888,9000,9001,9090,9091,9200,9300,10000,10443};
        count = sizeof(top100) / sizeof(top100[0]);
        memcpy(ports, top100, count * sizeof(int));
    }
    else if (strcmp(spec, "top1000") == 0) {
        /* Top 1000 ports */
        for (int i = 1; i <= 1000; i++) {
            ports[count++] = i;
        }
    }
    else if (strcmp(spec, "all") == 0) {
        for (int i = 1; i <= 65535; i++) {
            ports[count++] = i;
        }
    }
    else {
        /* Parse port range: "1-1000" or "80,443,8080" */
        char* spec_copy = strdup(spec);
        char* token = strtok(spec_copy, ",");
        
        while (token && count < MAX_PORTS) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                for (int p = start; p <= end && count < MAX_PORTS; p++) {
                    ports[count++] = p;
                }
            } else {
                ports[count++] = atoi(token);
            }
            token = strtok(NULL, ",");
        }
        free(spec_copy);
    }
    
    *ports_out = ports;
    return count;
}

/*
 * Export results to JSON
 */
int export_json(const char* filename, const char* target, 
                port_result_t* results, int count) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n  \"target\": \"%s\",\n  \"ports\": [\n", target);
    
    for (int i = 0; i < count; i++) {
        fprintf(fp, "    {\"port\": %d, \"state\": \"open\", \"service\": \"%s\"",
                results[i].port, results[i].service);
        if (results[i].banner_len > 0) {
            /* Escape JSON string */
            fprintf(fp, ", \"banner\": \"");
            for (int j = 0; j < results[i].banner_len && j < 100; j++) {
                char c = results[i].banner[j];
                if (c == '"') fprintf(fp, "\\\"");
                else if (c == '\\') fprintf(fp, "\\\\");
                else if (c == '\n') fprintf(fp, "\\n");
                else if (c == '\r') fprintf(fp, "\\r");
                else if (c >= 32) fputc(c, fp);
            }
            fprintf(fp, "\"");
        }
        fprintf(fp, "}%s\n", (i < count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ],\n  \"total_open\": %d\n}\n", count);
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

    if (argc < 2) {
        printf("Port Scanner - Pure C Implementation\n");
        printf("Usage: %s <target> [ports] [threads] [timeout_ms] [output.json]\n", argv[0]);
        printf("Ports: top100, top1000, all, 1-1000, 80,443,8080\n");
        printf("Example: %s scanme.nmap.org top100 50 1000 results.json\n", argv[0]);
        return 1;
    }
    
    const char* target = argv[1];
    const char* port_spec = (argc > 2) ? argv[2] : "top100";
    int threads = (argc > 3) ? atoi(argv[3]) : 50;
    int timeout = (argc > 4) ? atoi(argv[4]) : 1000;
    const char* output = (argc > 5) ? argv[5] : NULL;
    
    if (threads < 1) threads = 1;
    if (threads > 500) threads = 500;
    
    printf("\n=== Port Scanner ===\n");
    
    int* ports;
    int port_count = generate_port_list(port_spec, &ports);
    
    port_result_t* results;
    int open_count = scan_ports(target, ports, port_count, threads, timeout, &results);
    
    if (open_count < 0) {
        fprintf(stderr, "[-] Scan failed\n");
        free(ports);
        return 1;
    }
    
    /* Export if output specified */
    if (output && open_count > 0) {
        if (export_json(output, target, results, open_count) == 0) {
            printf("[*] Results exported to: %s\n", output);
        }
    }
    
    free(ports);
    free(results);
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
