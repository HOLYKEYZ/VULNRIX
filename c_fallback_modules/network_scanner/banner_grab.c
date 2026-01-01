/*
 * Banner Grabber - Pure C Implementation
 * Grabs service banners from open ports
 * Compile: gcc -O2 -pthread -o banner_grab banner_grab.c
 */

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
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
#include <ctype.h>

#define MAX_BANNER_LEN 4096
#define MAX_RESULTS 100
#define CONNECT_TIMEOUT_MS 3000
#define RECV_TIMEOUT_MS 2000

/* Service probes */
typedef struct {
    int port;
    const char* service;
    const char* probe;
    int probe_len;
} service_probe_t;

/* Banner result */
typedef struct {
    char host[256];
    int port;
    char service[64];
    char banner[MAX_BANNER_LEN];
    int banner_len;
    char version[128];
    int ssl;
} banner_result_t;

/* Service probes for different protocols */
static service_probe_t PROBES[] = {
    /* HTTP */
    {80, "http", "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", 0},
    {8080, "http-proxy", "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", 0},
    {8000, "http-alt", "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", 0},
    {8888, "http-alt2", "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", 0},
    
    /* FTP */
    {21, "ftp", NULL, 0},
    
    /* SSH */
    {22, "ssh", NULL, 0},
    
    /* Telnet */
    {23, "telnet", NULL, 0},
    
    /* SMTP */
    {25, "smtp", "EHLO scanner.local\r\n", 0},
    {587, "smtp-submission", "EHLO scanner.local\r\n", 0},
    
    /* DNS */
    {53, "dns", NULL, 0},
    
    /* POP3 */
    {110, "pop3", NULL, 0},
    {995, "pop3s", NULL, 0},
    
    /* IMAP */
    {143, "imap", NULL, 0},
    {993, "imaps", NULL, 0},
    
    /* MySQL */
    {3306, "mysql", NULL, 0},
    
    /* PostgreSQL */
    {5432, "postgresql", NULL, 0},
    
    /* Redis */
    {6379, "redis", "PING\r\n", 0},
    
    /* MongoDB */
    {27017, "mongodb", NULL, 0},
    
    /* RDP */
    {3389, "rdp", NULL, 0},
    
    /* VNC */
    {5900, "vnc", NULL, 0},
    {5901, "vnc", NULL, 0},
    
    /* SMB */
    {445, "smb", NULL, 0},
    {139, "netbios", NULL, 0},
    
    /* Generic */
    {0, "unknown", "\r\n", 0}
};

/*
 * Get probe for port
 */
service_probe_t* get_probe_for_port(int port) {
    for (int i = 0; PROBES[i].port != 0; i++) {
        if (PROBES[i].port == port) {
            return &PROBES[i];
        }
    }
    return &PROBES[sizeof(PROBES)/sizeof(PROBES[0]) - 1];  /* Generic */
}

/*
 * Set socket non-blocking
 */
int set_nonblocking(int sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

/*
 * Set socket blocking
 */
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
 * Clean banner - remove non-printable characters
 */
void clean_banner(char* banner, int len) {
    for (int i = 0; i < len; i++) {
        if (banner[i] < 32 && banner[i] != '\n' && banner[i] != '\r' && banner[i] != '\t') {
            banner[i] = '.';
        }
    }
}

/*
 * Extract version from banner
 */
void extract_version(const char* banner, const char* service, char* version, int max_len) {
    version[0] = '\0';
    
    /* SSH version */
    if (strstr(service, "ssh") && strncmp(banner, "SSH-", 4) == 0) {
        const char* end = strchr(banner, '\n');
        if (!end) end = strchr(banner, '\r');
        if (!end) end = banner + strlen(banner);
        int len = end - banner;
        if (len > max_len - 1) len = max_len - 1;
        strncpy(version, banner, len);
        version[len] = '\0';
        return;
    }
    
    /* HTTP Server header */
    if (strstr(service, "http")) {
        const char* server = strstr(banner, "Server:");
        if (!server) server = strstr(banner, "server:");
        if (server) {
            server += 7;
            while (*server == ' ') server++;
            const char* end = strchr(server, '\r');
            if (!end) end = strchr(server, '\n');
            if (end) {
                int len = end - server;
                if (len > max_len - 1) len = max_len - 1;
                strncpy(version, server, len);
                version[len] = '\0';
            }
        }
        return;
    }
    
    /* FTP banner */
    if (strstr(service, "ftp") && strncmp(banner, "220", 3) == 0) {
        const char* start = banner + 4;
        const char* end = strchr(start, '\r');
        if (!end) end = strchr(start, '\n');
        if (end) {
            int len = end - start;
            if (len > max_len - 1) len = max_len - 1;
            strncpy(version, start, len);
            version[len] = '\0';
        }
        return;
    }
    
    /* SMTP banner */
    if (strstr(service, "smtp") && strncmp(banner, "220", 3) == 0) {
        const char* start = banner + 4;
        const char* end = strchr(start, '\r');
        if (!end) end = strchr(start, '\n');
        if (end) {
            int len = end - start;
            if (len > max_len - 1) len = max_len - 1;
            strncpy(version, start, len);
            version[len] = '\0';
        }
        return;
    }
    
    /* MySQL banner */
    if (strstr(service, "mysql") && banner[0] != '\0') {
        /* MySQL greeting packet - version starts at offset 5 */
        if (strlen(banner) > 5) {
            const char* ver = banner + 5;
            const char* end = strchr(ver, '\0');
            if (end) {
                int len = end - ver;
                if (len > 50) len = 50;
                if (len > max_len - 1) len = max_len - 1;
                strncpy(version, ver, len);
                version[len] = '\0';
            }
        }
        return;
    }
    
    /* Redis */
    if (strstr(service, "redis") && strstr(banner, "+PONG")) {
        strncpy(version, "Redis Server", max_len - 1);
        version[max_len - 1] = '\0';
        return;
    }
    
    /* Generic - first line */
    const char* end = strchr(banner, '\r');
    if (!end) end = strchr(banner, '\n');
    if (end) {
        int len = end - banner;
        if (len > max_len - 1) len = max_len - 1;
        strncpy(version, banner, len);
        version[len] = '\0';
    }
}

/*
 * Grab banner from host:port
 */
/*
 * Grab banner from host:port
 * Secured: Uses getaddrinfo, proper string bounds
 */
int grab_banner(const char* host, int port, banner_result_t* result) {
    int sock = -1;
    struct addrinfo hints, *res = NULL, *p;
    char port_str[6];
    fd_set fdset;
    struct timeval tv;
    service_probe_t* probe;
    int bytes_read = 0;
    
    memset(result, 0, sizeof(banner_result_t));
    
    // Secure string copy for host
    strncpy(result->host, host, sizeof(result->host) - 1);
    result->host[sizeof(result->host) - 1] = '\0';
    result->port = port;
    
    /* Get probe for this port */
    probe = get_probe_for_port(port);
    strncpy(result->service, probe->service, sizeof(result->service) - 1);
    result->service[sizeof(result->service) - 1] = '\0'; // Ensure null term
    
    /* Resolve host using modern getaddrinfo */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;      // Force IPv4 for simplicity
    hints.ai_socktype = SOCK_STREAM;
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    /* Iterate results */
    for(p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) continue;

        /* Non-blocking connect */
        set_nonblocking(sock);
        connect(sock, p->ai_addr, p->ai_addrlen);
        
        /* Wait for connection */
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = CONNECT_TIMEOUT_MS / 1000;
        tv.tv_usec = (CONNECT_TIMEOUT_MS % 1000) * 1000;
        
        if (select(sock + 1, NULL, &fdset, NULL, &tv) > 0) {
            /* Check connection result */
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
            if (so_error == 0) {
                break; // Connected
            }
        }
        close(sock);
        sock = -1;
    }
    
    freeaddrinfo(res);
    
    if (sock == -1) return -1;
    
    set_blocking(sock);
    
    /* Set receive timeout */
    tv.tv_sec = RECV_TIMEOUT_MS / 1000;
    tv.tv_usec = (RECV_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    /* Send probe if needed */
    if (probe->probe) {
        char probe_buf[1024];
        /* Replace 'target' with actual host in HTTP probes */
        if (strstr(probe->probe, "Host: target")) {
            snprintf(probe_buf, sizeof(probe_buf), 
                     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
                     host);
            send(sock, probe_buf, strlen(probe_buf), 0);
        } else {
            send(sock, probe->probe, strlen(probe->probe), 0);
        }
    }
    
    /* Receive banner */
    bytes_read = recv(sock, result->banner, MAX_BANNER_LEN - 1, 0);
    if (bytes_read > 0) {
        result->banner[bytes_read] = '\0';
        result->banner_len = bytes_read;
        clean_banner(result->banner, bytes_read);
        extract_version(result->banner, result->service, result->version, sizeof(result->version));
    }
    
    close(sock);
    return bytes_read > 0 ? 0 : -1;
}

/*
 * Print result
 */
void print_result(banner_result_t* result) {
    printf("\n=== %s:%d (%s) ===\n", result->host, result->port, result->service);
    if (result->version[0]) {
        printf("Version: %s\n", result->version);
    }
    if (result->banner_len > 0) {
        printf("Banner (%d bytes):\n", result->banner_len);
        /* Print first 500 chars */
        int print_len = result->banner_len > 500 ? 500 : result->banner_len;
        printf("%.500s", result->banner);
        if (result->banner_len > 500) {
            printf("\n... [truncated]");
        }
        printf("\n");
    }
}

/*
 * Export to JSON
 */
int export_json(const char* filename, banner_result_t* results, int count) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n  \"banners\": [\n");
    
    for (int i = 0; i < count; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"host\": \"%s\",\n", results[i].host);
        fprintf(fp, "      \"port\": %d,\n", results[i].port);
        fprintf(fp, "      \"service\": \"%s\",\n", results[i].service);
        fprintf(fp, "      \"version\": \"%s\",\n", results[i].version);
        fprintf(fp, "      \"banner_length\": %d\n", results[i].banner_len);
        fprintf(fp, "    }%s\n", (i < count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ],\n  \"total\": %d\n}\n", count);
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
        printf("Banner Grabber - Pure C Implementation\n");
        printf("Usage: %s <host> <port1,port2,...> [output.json]\n", argv[0]);
        printf("Example: %s scanme.nmap.org 22,80,443 results.json\n", argv[0]);
        return 1;
    }
    
    const char* host = argv[1];
    const char* ports_str = argv[2];
    const char* output = (argc > 3) ? argv[3] : NULL;
    
    printf("\n=== Banner Grabber ===\n");
    printf("[*] Target: %s\n", host);
    printf("[*] Ports: %s\n", ports_str);
    
    /* Parse ports */
    int ports[100];
    int port_count = 0;
    char* ports_copy = strdup(ports_str);
    char* token = strtok(ports_copy, ",");
    
    while (token && port_count < 100) {
        ports[port_count++] = atoi(token);
        token = strtok(NULL, ",");
    }
    free(ports_copy);
    
    /* Grab banners */
    banner_result_t* results = calloc(port_count, sizeof(banner_result_t));
    if (!results) {
        fprintf(stderr, "[-] Memory allocation failed\n");
        return 1;
    }
    int success_count = 0;
    
    for (int i = 0; i < port_count; i++) {
        printf("\n[*] Grabbing banner from port %d...\n", ports[i]);
        
        if (grab_banner(host, ports[i], &results[success_count]) == 0) {
            print_result(&results[success_count]);
            success_count++;
        } else {
            printf("[-] Failed to grab banner from port %d\n", ports[i]);
        }
    }
    
    printf("\n[*] Successfully grabbed %d/%d banners\n", success_count, port_count);
    
    /* Export if output specified */
    if (output && success_count > 0) {
        if (export_json(output, results, success_count) == 0) {
            printf("[*] Results exported to: %s\n", output);
        }
    }
    
    free(results);
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
