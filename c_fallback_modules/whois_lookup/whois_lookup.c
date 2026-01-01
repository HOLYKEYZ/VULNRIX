/*
 * WHOIS Lookup - Pure C Implementation
 * Raw socket WHOIS queries
 * Compile: gcc -O2 -o whois_lookup whois_lookup.c
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
#include <ctype.h>
#include <time.h>

#define WHOIS_PORT 43
#define MAX_RESPONSE 65536
#define MAX_FIELD_LEN 256
#define TIMEOUT_SEC 10

/* WHOIS result structure */
typedef struct {
    char domain[MAX_FIELD_LEN];
    char registrar[MAX_FIELD_LEN];
    char creation_date[MAX_FIELD_LEN];
    char expiration_date[MAX_FIELD_LEN];
    char updated_date[MAX_FIELD_LEN];
    char name_servers[10][MAX_FIELD_LEN];
    int ns_count;
    char status[10][MAX_FIELD_LEN];
    int status_count;
    char registrant_name[MAX_FIELD_LEN];
    char registrant_org[MAX_FIELD_LEN];
    char registrant_country[MAX_FIELD_LEN];
    char raw[MAX_RESPONSE];
    int raw_len;
    char whois_server[MAX_FIELD_LEN];
} whois_result_t;

/* WHOIS server mapping */
typedef struct {
    const char* tld;
    const char* server;
} whois_server_t;

static whois_server_t WHOIS_SERVERS[] = {
    {"com", "whois.verisign-grs.com"},
    {"net", "whois.verisign-grs.com"},
    {"org", "whois.pir.org"},
    {"info", "whois.afilias.net"},
    {"io", "whois.nic.io"},
    {"co", "whois.nic.co"},
    {"me", "whois.nic.me"},
    {"us", "whois.nic.us"},
    {"uk", "whois.nic.uk"},
    {"de", "whois.denic.de"},
    {"fr", "whois.nic.fr"},
    {"eu", "whois.eu"},
    {"ru", "whois.tcinet.ru"},
    {"cn", "whois.cnnic.cn"},
    {"jp", "whois.jprs.jp"},
    {"au", "whois.auda.org.au"},
    {"ca", "whois.cira.ca"},
    {"br", "whois.registro.br"},
    {"in", "whois.registry.in"},
    {"nl", "whois.domain-registry.nl"},
    {"be", "whois.dns.be"},
    {"ch", "whois.nic.ch"},
    {"at", "whois.nic.at"},
    {"pl", "whois.dns.pl"},
    {"se", "whois.iis.se"},
    {"no", "whois.norid.no"},
    {"fi", "whois.fi"},
    {"dk", "whois.dk-hostmaster.dk"},
    {"cz", "whois.nic.cz"},
    {"sk", "whois.sk-nic.sk"},
    {"hu", "whois.nic.hu"},
    {"ro", "whois.rotld.ro"},
    {"bg", "whois.register.bg"},
    {"ua", "whois.ua"},
    {"kr", "whois.kr"},
    {"tw", "whois.twnic.net.tw"},
    {"hk", "whois.hkirc.hk"},
    {"sg", "whois.sgnic.sg"},
    {"my", "whois.mynic.my"},
    {"th", "whois.thnic.co.th"},
    {"id", "whois.pandi.or.id"},
    {"ph", "whois.dot.ph"},
    {"vn", "whois.vnnic.vn"},
    {"nz", "whois.srs.net.nz"},
    {"mx", "whois.mx"},
    {"ar", "whois.nic.ar"},
    {"cl", "whois.nic.cl"},
    {"co", "whois.nic.co"},
    {"pe", "kero.yachay.pe"},
    {"za", "whois.registry.net.za"},
    {"eg", "whois.ripe.net"},
    {"ng", "whois.nic.net.ng"},
    {"ke", "whois.kenic.or.ke"},
    {NULL, "whois.iana.org"}  /* Default */
};

/* IP WHOIS servers */
static const char* IP_WHOIS_SERVERS[] = {
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net",
    NULL
};

/*
 * Get WHOIS server for TLD
 */
const char* get_whois_server(const char* domain) {
    /* Extract TLD */
    const char* dot = strrchr(domain, '.');
    if (!dot) return "whois.iana.org";
    
    const char* tld = dot + 1;
    
    for (int i = 0; WHOIS_SERVERS[i].tld != NULL; i++) {
        if (strcasecmp(WHOIS_SERVERS[i].tld, tld) == 0) {
            return WHOIS_SERVERS[i].server;
        }
    }
    
    return "whois.iana.org";
}

/*
 * Send WHOIS query and receive response
 */
/*
 * Send WHOIS query and receive response
 */
int query_whois(const char* server, const char* query, char* response, int max_len) {
    int sock;
    struct addrinfo hints, *res;
    char send_buf[512];
    int total_bytes = 0;
    int bytes_read;
    
    /* Resolve WHOIS server */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(server, "43", &hints, &res) != 0) {
        fprintf(stderr, "[-] Failed to resolve WHOIS server: %s\n", server);
        return -1;
    }
    
    /* Create socket */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    /* Connect */
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    
    freeaddrinfo(res);
    
    /* Send query */
    snprintf(send_buf, sizeof(send_buf), "%s\r\n", query);
    if (send(sock, send_buf, strlen(send_buf), 0) < 0) {
        perror("send");
        close(sock);
        return -1;
    }
    
    /* Receive response */
    while (total_bytes < max_len - 1) {
        bytes_read = recv(sock, response + total_bytes, max_len - total_bytes - 1, 0);
        if (bytes_read <= 0) break;
        total_bytes += bytes_read;
    }
    
    response[total_bytes] = '\0';
    close(sock);
    
    return total_bytes;
}

/*
 * Trim whitespace from string
 */
char* trim(char* str) {
    char* end;
    
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

/*
 * Parse WHOIS response
 */
void parse_whois(const char* raw, whois_result_t* result) {
    char line[1024];
    const char* ptr = raw;
    const char* end;
    
    result->ns_count = 0;
    result->status_count = 0;
    
    while (*ptr) {
        /* Find end of line */
        end = strchr(ptr, '\n');
        if (!end) end = ptr + strlen(ptr);
        
        int len = end - ptr;
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        
        strncpy(line, ptr, len);
        line[len] = '\0';
        
        /* Remove carriage return */
        char* cr = strchr(line, '\r');
        if (cr) *cr = '\0';
        
        /* Skip comments and empty lines */
        char* trimmed = trim(line);
        if (*trimmed == '%' || *trimmed == '#' || *trimmed == '\0') {
            ptr = (*end) ? end + 1 : end;
            continue;
        }
        
        /* Parse key: value */
        char* colon = strchr(trimmed, ':');
        if (colon) {
            *colon = '\0';
            char* key = trim(trimmed);
            char* value = trim(colon + 1);
            
            /* Convert key to lowercase for comparison */
            char key_lower[256];
            strncpy(key_lower, key, sizeof(key_lower) - 1);
            for (int i = 0; key_lower[i]; i++) {
                key_lower[i] = tolower(key_lower[i]);
            }
            
            /* Match fields */
            if (strstr(key_lower, "registrar") && !result->registrar[0]) {
                strncpy(result->registrar, value, MAX_FIELD_LEN - 1);
            }
            else if ((strstr(key_lower, "creation") || strstr(key_lower, "created")) 
                     && !result->creation_date[0]) {
                strncpy(result->creation_date, value, MAX_FIELD_LEN - 1);
            }
            else if (strstr(key_lower, "expir") && !result->expiration_date[0]) {
                strncpy(result->expiration_date, value, MAX_FIELD_LEN - 1);
            }
            else if ((strstr(key_lower, "updated") || strstr(key_lower, "modified"))
                     && !result->updated_date[0]) {
                strncpy(result->updated_date, value, MAX_FIELD_LEN - 1);
            }
            else if ((strstr(key_lower, "name server") || strstr(key_lower, "nserver"))
                     && result->ns_count < 10) {
                /* Check for duplicates */
                int dup = 0;
                for (int i = 0; i < result->ns_count; i++) {
                    if (strcasecmp(result->name_servers[i], value) == 0) {
                        dup = 1;
                        break;
                    }
                }
                if (!dup) {
                    strncpy(result->name_servers[result->ns_count], value, MAX_FIELD_LEN - 1);
                    result->ns_count++;
                }
            }
            else if (strstr(key_lower, "status") && result->status_count < 10) {
                strncpy(result->status[result->status_count], value, MAX_FIELD_LEN - 1);
                result->status_count++;
            }
            else if (strstr(key_lower, "registrant") && strstr(key_lower, "name")
                     && !result->registrant_name[0]) {
                strncpy(result->registrant_name, value, MAX_FIELD_LEN - 1);
            }
            else if (strstr(key_lower, "registrant") && strstr(key_lower, "org")
                     && !result->registrant_org[0]) {
                strncpy(result->registrant_org, value, MAX_FIELD_LEN - 1);
            }
            else if (strstr(key_lower, "registrant") && strstr(key_lower, "country")
                     && !result->registrant_country[0]) {
                strncpy(result->registrant_country, value, MAX_FIELD_LEN - 1);
            }
        }
        
        ptr = (*end) ? end + 1 : end;
    }
}

/*
 * Perform WHOIS lookup for domain
 */
int whois_lookup(const char* domain, whois_result_t* result) {
    char response[MAX_RESPONSE];
    const char* server;
    int len;
    
    memset(result, 0, sizeof(whois_result_t));
    strncpy(result->domain, domain, MAX_FIELD_LEN - 1);
    
    /* Get WHOIS server */
    server = get_whois_server(domain);
    strncpy(result->whois_server, server, MAX_FIELD_LEN - 1);
    
    printf("[*] Querying %s for %s\n", server, domain);
    
    /* Query WHOIS */
    len = query_whois(server, domain, response, sizeof(response));
    if (len < 0) {
        return -1;
    }
    
    /* Store raw response */
    result->raw_len = len;
    strncpy(result->raw, response, MAX_RESPONSE - 1);
    
    /* Parse response */
    parse_whois(response, result);
    
    return 0;
}

/*
 * Perform WHOIS lookup for IP address
 */
int whois_ip_lookup(const char* ip, whois_result_t* result) {
    char response[MAX_RESPONSE];
    int len;
    
    memset(result, 0, sizeof(whois_result_t));
    strncpy(result->domain, ip, MAX_FIELD_LEN - 1);
    
    /* Try each IP WHOIS server */
    for (int i = 0; IP_WHOIS_SERVERS[i] != NULL; i++) {
        printf("[*] Trying %s for %s\n", IP_WHOIS_SERVERS[i], ip);
        
        len = query_whois(IP_WHOIS_SERVERS[i], ip, response, sizeof(response));
        if (len > 0 && strstr(response, "No match") == NULL 
            && strstr(response, "not found") == NULL) {
            strncpy(result->whois_server, IP_WHOIS_SERVERS[i], MAX_FIELD_LEN - 1);
            result->raw_len = len;
            strncpy(result->raw, response, MAX_RESPONSE - 1);
            return 0;
        }
    }
    
    return -1;
}

/*
 * Print WHOIS result
 */
void print_result(whois_result_t* result) {
    printf("\n=== WHOIS Result ===\n");
    printf("Domain: %s\n", result->domain);
    printf("WHOIS Server: %s\n", result->whois_server);
    
    if (result->registrar[0])
        printf("Registrar: %s\n", result->registrar);
    if (result->creation_date[0])
        printf("Created: %s\n", result->creation_date);
    if (result->expiration_date[0])
        printf("Expires: %s\n", result->expiration_date);
    if (result->updated_date[0])
        printf("Updated: %s\n", result->updated_date);
    
    if (result->ns_count > 0) {
        printf("Name Servers:\n");
        for (int i = 0; i < result->ns_count; i++) {
            printf("  - %s\n", result->name_servers[i]);
        }
    }
    
    if (result->status_count > 0) {
        printf("Status:\n");
        for (int i = 0; i < result->status_count; i++) {
            printf("  - %s\n", result->status[i]);
        }
    }
    
    if (result->registrant_name[0] || result->registrant_org[0]) {
        printf("Registrant:\n");
        if (result->registrant_name[0])
            printf("  Name: %s\n", result->registrant_name);
        if (result->registrant_org[0])
            printf("  Organization: %s\n", result->registrant_org);
        if (result->registrant_country[0])
            printf("  Country: %s\n", result->registrant_country);
    }
}

/*
 * Export to JSON
 */
int export_json(const char* filename, whois_result_t* result) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"domain\": \"%s\",\n", result->domain);
    fprintf(fp, "  \"whois_server\": \"%s\",\n", result->whois_server);
    fprintf(fp, "  \"registrar\": \"%s\",\n", result->registrar);
    fprintf(fp, "  \"creation_date\": \"%s\",\n", result->creation_date);
    fprintf(fp, "  \"expiration_date\": \"%s\",\n", result->expiration_date);
    fprintf(fp, "  \"updated_date\": \"%s\",\n", result->updated_date);
    
    fprintf(fp, "  \"name_servers\": [");
    for (int i = 0; i < result->ns_count; i++) {
        fprintf(fp, "\"%s\"%s", result->name_servers[i], 
                (i < result->ns_count - 1) ? ", " : "");
    }
    fprintf(fp, "],\n");
    
    fprintf(fp, "  \"status\": [");
    for (int i = 0; i < result->status_count; i++) {
        fprintf(fp, "\"%s\"%s", result->status[i],
                (i < result->status_count - 1) ? ", " : "");
    }
    fprintf(fp, "],\n");
    
    fprintf(fp, "  \"registrant\": {\n");
    fprintf(fp, "    \"name\": \"%s\",\n", result->registrant_name);
    fprintf(fp, "    \"organization\": \"%s\",\n", result->registrant_org);
    fprintf(fp, "    \"country\": \"%s\"\n", result->registrant_country);
    fprintf(fp, "  }\n");
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

    if (argc < 2) {
        printf("WHOIS Lookup - Pure C Implementation\n");
        printf("Usage: %s <domain|ip> [output.json] [--raw]\n", argv[0]);
        printf("Example: %s example.com result.json\n", argv[0]);
        printf("         %s 8.8.8.8\n", argv[0]);
        return 1;
    }
    
    const char* target = argv[1];
    const char* output = (argc > 2 && argv[2][0] != '-') ? argv[2] : NULL;
    int show_raw = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--raw") == 0) show_raw = 1;
    }
    
    printf("\n=== WHOIS Lookup ===\n");
    printf("[*] Target: %s\n", target);
    
    whois_result_t result;
    int ret;
    
    /* Check if IP or domain */
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) == 1) {
        ret = whois_ip_lookup(target, &result);
    } else {
        ret = whois_lookup(target, &result);
    }
    
    if (ret < 0) {
        fprintf(stderr, "[-] WHOIS lookup failed\n");
        return 1;
    }
    
    print_result(&result);
    
    if (show_raw) {
        printf("\n=== Raw Response ===\n%s\n", result.raw);
    }
    
    if (output) {
        if (export_json(output, &result) == 0) {
            printf("\n[*] Results exported to: %s\n", output);
        }
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
