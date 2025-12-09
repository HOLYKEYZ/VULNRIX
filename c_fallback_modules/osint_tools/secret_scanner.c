/*
 * Secret Scanner - Pure C Implementation
 * Scans files for hardcoded secrets, API keys, passwords
 * Compile: gcc -O2 -o secret_scanner secret_scanner.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #define PATH_SEP '\\'
#else
    #include <dirent.h>
    #include <unistd.h>
    #define PATH_SEP '/'
#endif

#define MAX_LINE_LEN 4096
#define MAX_FINDINGS 1000
#define MAX_PATH_LEN 1024

/* Secret types */
typedef enum {
    SECRET_AWS, SECRET_GITHUB, SECRET_SLACK, SECRET_STRIPE,
    SECRET_GOOGLE, SECRET_PRIVATE_KEY, SECRET_PASSWORD,
    SECRET_API_KEY, SECRET_TOKEN, SECRET_JWT, SECRET_GENERIC
} secret_type_t;

/* Finding structure */
typedef struct {
    char file[MAX_PATH_LEN];
    int line_number;
    char line[512];
    char matched[256];
    const char* type_name;
    int severity;
} finding_t;

/* Pattern structure */
typedef struct {
    const char* name;
    const char* pattern;
    int min_len;
    int severity;
} pattern_t;

/* Secret patterns */
static pattern_t PATTERNS[] = {
    {"AWS Access Key", "AKIA", 20, 9},
    {"GitHub Token", "ghp_", 36, 9},
    {"GitHub OAuth", "gho_", 36, 9},
    {"Slack Token", "xoxb-", 50, 8},
    {"Slack Token", "xoxp-", 50, 8},
    {"Stripe Secret", "sk_live_", 24, 10},
    {"Stripe Test", "sk_test_", 24, 5},
    {"Google API Key", "AIza", 35, 8},
    {"JWT Token", "eyJ", 100, 7},
    {"Private Key", "-----BEGIN RSA PRIVATE KEY-----", 0, 10},
    {"Private Key", "-----BEGIN PRIVATE KEY-----", 0, 10},
    {"Private Key", "-----BEGIN EC PRIVATE KEY-----", 0, 10},
    {"Password", "password=", 8, 8},
    {"Password", "password:", 8, 8},
    {"API Key", "api_key=", 16, 7},
    {"API Key", "apikey=", 16, 7},
    {"Secret", "secret=", 16, 7},
    {"Auth Token", "auth_token=", 20, 8},
    {"Access Token", "access_token=", 20, 8},
    {"Bearer Token", "Bearer ", 20, 8},
    {NULL, NULL, 0, 0}
};

/* Scan extensions */
static const char* EXTENSIONS[] = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp",
    ".json", ".yaml", ".yml", ".xml", ".env", ".sh", ".sql", NULL
};

/* Skip directories */
static const char* SKIP_DIRS[] = {
    "node_modules", ".git", "__pycache__", ".venv", "vendor", "dist", NULL
};

static finding_t findings[MAX_FINDINGS];
static int finding_count = 0;
static int files_scanned = 0;

/*
 * Check file extension
 */
int should_scan(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    for (int i = 0; EXTENSIONS[i]; i++) {
        if (strcasecmp(ext, EXTENSIONS[i]) == 0) return 1;
    }
    return 0;
}

/*
 * Check skip directory
 */
int should_skip(const char* dirname) {
    for (int i = 0; SKIP_DIRS[i]; i++) {
        if (strcmp(dirname, SKIP_DIRS[i]) == 0) return 1;
    }
    return 0;
}

/*
 * Extract secret value
 */
int extract_secret(const char* line, int pos, char* out, int max) {
    int i = pos, j = 0;
    while (line[i] && (line[i] == ' ' || line[i] == '"' || line[i] == '\'' || line[i] == '=')) i++;
    while (line[i] && j < max - 1) {
        if (line[i] == '"' || line[i] == '\'' || line[i] == '\n' || 
            line[i] == ' ' || line[i] == ';') break;
        out[j++] = line[i++];
    }
    out[j] = '\0';
    return j;
}

/*
 * Scan line for secrets
 */
void scan_line(const char* filepath, const char* line, int line_num) {
    char lower[MAX_LINE_LEN];
    strncpy(lower, line, MAX_LINE_LEN - 1);
    for (int i = 0; lower[i]; i++) lower[i] = tolower(lower[i]);
    
    for (int p = 0; PATTERNS[p].name; p++) {
        const char* match = NULL;
        
        /* Case-sensitive for tokens starting with specific prefixes */
        if (PATTERNS[p].pattern[0] >= 'A' && PATTERNS[p].pattern[0] <= 'Z') {
            match = strstr(line, PATTERNS[p].pattern);
        } else {
            match = strstr(lower, PATTERNS[p].pattern);
            if (match) match = line + (match - lower);
        }
        
        if (match && finding_count < MAX_FINDINGS) {
            finding_t* f = &findings[finding_count];
            strncpy(f->file, filepath, MAX_PATH_LEN - 1);
            f->line_number = line_num;
            f->type_name = PATTERNS[p].name;
            f->severity = PATTERNS[p].severity;
            
            strncpy(f->line, line, 500);
            char* nl = strchr(f->line, '\n');
            if (nl) *nl = '\0';
            
            int pos = match - line + strlen(PATTERNS[p].pattern);
            int len = extract_secret(line, pos, f->matched, sizeof(f->matched));
            
            if (PATTERNS[p].min_len > 0 && len < PATTERNS[p].min_len) continue;
            
            finding_count++;
            printf("[!] %s in %s:%d (sev:%d)\n", f->type_name, filepath, line_num, f->severity);
        }
    }
}

/*
 * Scan file
 */
int scan_file(const char* filepath) {
    FILE* fp = fopen(filepath, "r");
    if (!fp) return -1;
    
    char line[MAX_LINE_LEN];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        scan_line(filepath, line, line_num);
    }
    
    fclose(fp);
    files_scanned++;
    return 0;
}

#ifndef _WIN32
/*
 * Scan directory recursively (Unix)
 */
int scan_directory(const char* dirpath) {
    DIR* dir = opendir(dirpath);
    if (!dir) return -1;
    
    struct dirent* entry;
    char path[MAX_PATH_LEN];
    struct stat st;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (should_skip(entry->d_name)) continue;
        
        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);
        if (stat(path, &st) < 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            scan_directory(path);
        } else if (S_ISREG(st.st_mode) && should_scan(entry->d_name)) {
            scan_file(path);
        }
    }
    
    closedir(dir);
    return 0;
}
#else
/*
 * Scan directory recursively (Windows)
 */
int scan_directory(const char* dirpath) {
    WIN32_FIND_DATA fd;
    char pattern[MAX_PATH_LEN];
    snprintf(pattern, sizeof(pattern), "%s\\*", dirpath);
    
    HANDLE h = FindFirstFile(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    
    do {
        if (fd.cFileName[0] == '.') continue;
        if (should_skip(fd.cFileName)) continue;
        
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s\\%s", dirpath, fd.cFileName);
        
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory(path);
        } else if (should_scan(fd.cFileName)) {
            scan_file(path);
        }
    } while (FindNextFile(h, &fd));
    
    FindClose(h);
    return 0;
}
#endif

/*
 * Print summary
 */
void print_summary() {
    printf("\n=== Scan Summary ===\n");
    printf("Files scanned: %d\n", files_scanned);
    printf("Secrets found: %d\n\n", finding_count);
    
    int crit = 0, high = 0, med = 0;
    for (int i = 0; i < finding_count; i++) {
        if (findings[i].severity >= 9) crit++;
        else if (findings[i].severity >= 7) high++;
        else med++;
    }
    
    printf("Critical: %d\n", crit);
    printf("High: %d\n", high);
    printf("Medium/Low: %d\n", med);
}

/*
 * Export JSON
 */
int export_json(const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n  \"findings\": [\n");
    for (int i = 0; i < finding_count; i++) {
        fprintf(fp, "    {\"file\":\"%s\",\"line\":%d,\"type\":\"%s\",\"severity\":%d}%s\n",
                findings[i].file, findings[i].line_number, 
                findings[i].type_name, findings[i].severity,
                (i < finding_count - 1) ? "," : "");
    }
    fprintf(fp, "  ],\n  \"total\": %d\n}\n", finding_count);
    
    fclose(fp);
    return 0;
}

/*
 * Main
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Secret Scanner - Pure C Implementation\n");
        printf("Usage: %s <path> [output.json]\n", argv[0]);
        printf("Example: %s ./src secrets.json\n", argv[0]);
        return 1;
    }
    
    const char* target = argv[1];
    const char* output = (argc > 2) ? argv[2] : NULL;
    
    printf("\n=== Secret Scanner ===\n");
    printf("[*] Scanning: %s\n\n", target);
    
    struct stat st;
    if (stat(target, &st) < 0) {
        fprintf(stderr, "[-] Cannot access: %s\n", target);
        return 1;
    }
    
    clock_t start = clock();
    
    if (S_ISDIR(st.st_mode)) {
        scan_directory(target);
    } else {
        scan_file(target);
    }
    
    double duration = (double)(clock() - start) / CLOCKS_PER_SEC;
    
    print_summary();
    printf("\nScan time: %.2f seconds\n", duration);
    
    if (output) {
        export_json(output);
        printf("[*] Results exported to: %s\n", output);
    }
    
    return finding_count > 0 ? 1 : 0;
}
