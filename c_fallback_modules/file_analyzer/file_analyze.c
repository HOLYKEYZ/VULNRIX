/*
 * File Analyzer - Pure C Implementation
 * Analyzes files for suspicious patterns and malware indicators
 * Compile: gcc -O2 -o file_analyze file_analyze.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/stat.h>
#endif

#define MAX_FILE_SIZE (50 * 1024 * 1024)  /* 50MB */
#define MAX_PATTERNS 100
#define MAX_FINDINGS 500

/* Risk levels */
typedef enum {
    RISK_LOW = 1,
    RISK_MEDIUM = 5,
    RISK_HIGH = 8,
    RISK_CRITICAL = 10
} risk_level_t;

/* Finding structure */
typedef struct {
    char pattern_name[64];
    char matched[256];
    int line_number;
    int offset;
    int risk;
} finding_t;

/* Analysis result */
typedef struct {
    char filename[1024];
    uint64_t file_size;
    char file_type[64];
    char md5[33];
    char sha256[65];
    int risk_score;
    const char* risk_level;
    finding_t findings[MAX_FINDINGS];
    int finding_count;
    double analysis_time;
} analysis_result_t;

/* Suspicious patterns */
typedef struct {
    const char* name;
    const char* pattern;
    int risk;
    int binary_only;
} suspicious_pattern_t;

static suspicious_pattern_t PATTERNS[] = {
    /* Shell commands */
    {"Shell Execution", "os.system(", RISK_HIGH, 0},
    {"Shell Execution", "subprocess.call(", RISK_HIGH, 0},
    {"Shell Execution", "subprocess.Popen(", RISK_HIGH, 0},
    {"Shell Execution", "exec(", RISK_HIGH, 0},
    {"Shell Execution", "eval(", RISK_HIGH, 0},
    {"Shell Execution", "shell_exec(", RISK_HIGH, 0},
    {"Shell Execution", "system(", RISK_MEDIUM, 0},
    {"Shell Execution", "passthru(", RISK_HIGH, 0},
    {"Shell Execution", "popen(", RISK_MEDIUM, 0},
    
    /* Network */
    {"Network Socket", "socket.socket(", RISK_MEDIUM, 0},
    {"Network Socket", "socket(AF_INET", RISK_MEDIUM, 0},
    {"HTTP Request", "urllib.request", RISK_LOW, 0},
    {"HTTP Request", "requests.get(", RISK_LOW, 0},
    {"HTTP Request", "requests.post(", RISK_LOW, 0},
    {"HTTP Request", "curl_exec(", RISK_MEDIUM, 0},
    
    /* File operations */
    {"File Write", "open(", RISK_LOW, 0},
    {"File Delete", "os.remove(", RISK_MEDIUM, 0},
    {"File Delete", "unlink(", RISK_MEDIUM, 0},
    {"File Delete", "shutil.rmtree(", RISK_HIGH, 0},
    
    /* Encoding/Obfuscation */
    {"Base64 Decode", "base64.b64decode(", RISK_MEDIUM, 0},
    {"Base64 Decode", "base64_decode(", RISK_MEDIUM, 0},
    {"Hex Encoding", "\\x", RISK_LOW, 0},
    {"Char Encoding", "chr(", RISK_LOW, 0},
    {"String Obfuscation", "fromCharCode", RISK_MEDIUM, 0},
    
    /* Credentials */
    {"Hardcoded Password", "password=", RISK_HIGH, 0},
    {"Hardcoded Password", "passwd=", RISK_HIGH, 0},
    {"API Key", "api_key=", RISK_HIGH, 0},
    {"API Key", "apikey=", RISK_HIGH, 0},
    {"Secret Key", "secret_key=", RISK_HIGH, 0},
    {"Private Key", "-----BEGIN PRIVATE KEY-----", RISK_CRITICAL, 0},
    {"Private Key", "-----BEGIN RSA PRIVATE KEY-----", RISK_CRITICAL, 0},
    
    /* Binary patterns */
    {"PE Executable", "MZ", RISK_HIGH, 1},
    {"ELF Binary", "\x7fELF", RISK_HIGH, 1},
    {"Shell Script", "#!/bin/", RISK_MEDIUM, 0},
    {"PowerShell", "powershell", RISK_HIGH, 0},
    {"PowerShell", "-EncodedCommand", RISK_CRITICAL, 0},
    
    /* Malware indicators */
    {"Keylogger", "GetAsyncKeyState", RISK_CRITICAL, 0},
    {"Keylogger", "SetWindowsHookEx", RISK_CRITICAL, 0},
    {"Screen Capture", "GetDesktopWindow", RISK_HIGH, 0},
    {"Registry Access", "RegOpenKeyEx", RISK_MEDIUM, 0},
    {"Process Injection", "VirtualAllocEx", RISK_CRITICAL, 0},
    {"Process Injection", "WriteProcessMemory", RISK_CRITICAL, 0},
    {"Anti-Debug", "IsDebuggerPresent", RISK_HIGH, 0},
    
    {NULL, NULL, 0, 0}
};

/* Suspicious extensions */
static const char* HIGH_RISK_EXT[] = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".ws", ".wsf", ".msc", ".msi", ".msp", ".hta",
    NULL
};

static const char* MEDIUM_RISK_EXT[] = {
    ".dll", ".sys", ".drv", ".ocx", ".cpl", ".jar", ".ps1", ".psm1", ".reg",
    NULL
};

/*
 * Check file extension risk
 */
int get_extension_risk(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return RISK_LOW;
    
    for (int i = 0; HIGH_RISK_EXT[i]; i++) {
        if (strcasecmp(ext, HIGH_RISK_EXT[i]) == 0) return RISK_HIGH;
    }
    for (int i = 0; MEDIUM_RISK_EXT[i]; i++) {
        if (strcasecmp(ext, MEDIUM_RISK_EXT[i]) == 0) return RISK_MEDIUM;
    }
    return RISK_LOW;
}

/*
 * Detect file type from magic bytes
 */
const char* detect_file_type(const uint8_t* data, size_t len) {
    if (len < 4) return "unknown";
    
    /* PE executable */
    if (data[0] == 'M' && data[1] == 'Z') return "PE Executable";
    
    /* ELF */
    if (data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')
        return "ELF Binary";
    
    /* PDF */
    if (data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F')
        return "PDF Document";
    
    /* ZIP/Office */
    if (data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04)
        return "ZIP Archive";
    
    /* GZIP */
    if (data[0] == 0x1f && data[1] == 0x8b) return "GZIP Archive";
    
    /* PNG */
    if (data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G')
        return "PNG Image";
    
    /* JPEG */
    if (data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff)
        return "JPEG Image";
    
    /* Check if text */
    int text_chars = 0;
    for (size_t i = 0; i < len && i < 1000; i++) {
        if (isprint(data[i]) || isspace(data[i])) text_chars++;
    }
    if (text_chars > 900) return "Text File";
    
    return "Binary";
}

/*
 * Simple MD5 (same as file_hash.c)
 */
void compute_md5(const uint8_t* data, size_t len, char* hash_out);

/*
 * Scan content for patterns
 */
int scan_patterns(const char* content, size_t len, analysis_result_t* result, int is_binary) {
    int line_num = 1;
    
    for (int p = 0; PATTERNS[p].name && result->finding_count < MAX_FINDINGS; p++) {
        if (PATTERNS[p].binary_only && !is_binary) continue;
        
        const char* ptr = content;
        while ((ptr = strstr(ptr, PATTERNS[p].pattern)) != NULL) {
            if (result->finding_count >= MAX_FINDINGS) break;
            
            finding_t* f = &result->findings[result->finding_count];
            strncpy(f->pattern_name, PATTERNS[p].name, sizeof(f->pattern_name) - 1);
            f->risk = PATTERNS[p].risk;
            f->offset = ptr - content;
            
            /* Count line number */
            f->line_number = 1;
            for (const char* c = content; c < ptr; c++) {
                if (*c == '\n') f->line_number++;
            }
            
            /* Extract context */
            int ctx_start = (ptr - content > 20) ? -20 : -(ptr - content);
            int ctx_len = 50;
            strncpy(f->matched, ptr + ctx_start, ctx_len);
            f->matched[ctx_len] = '\0';
            
            result->finding_count++;
            ptr++;
        }
    }
    
    return result->finding_count;
}

/*
 * Calculate risk score
 */
int calculate_risk_score(analysis_result_t* result) {
    int score = 0;
    
    /* Extension risk */
    score += get_extension_risk(result->filename) * 5;
    
    /* Pattern risks */
    for (int i = 0; i < result->finding_count; i++) {
        score += result->findings[i].risk * 2;
    }
    
    /* Cap at 100 */
    if (score > 100) score = 100;
    
    result->risk_score = score;
    
    if (score >= 70) result->risk_level = "CRITICAL";
    else if (score >= 50) result->risk_level = "HIGH";
    else if (score >= 30) result->risk_level = "MEDIUM";
    else result->risk_level = "LOW";
    
    return score;
}

/*
 * Analyze file
 */
int analyze_file(const char* filepath, analysis_result_t* result) {
    FILE* fp;
    uint8_t* content;
    size_t file_size;
    clock_t start;
    
    memset(result, 0, sizeof(analysis_result_t));
    strncpy(result->filename, filepath, sizeof(result->filename) - 1);
    
    fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "[-] Cannot open file: %s\n", filepath);
        return -1;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    result->file_size = file_size;
    
    if (file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "[-] File too large: %zu bytes\n", file_size);
        fclose(fp);
        return -1;
    }
    
    /* Read file */
    content = malloc(file_size + 1);
    if (!content) {
        fclose(fp);
        return -1;
    }
    
    fread(content, 1, file_size, fp);
    content[file_size] = '\0';
    fclose(fp);
    
    start = clock();
    
    /* Detect file type */
    strncpy(result->file_type, detect_file_type(content, file_size), sizeof(result->file_type) - 1);
    
    /* Check if binary */
    int is_binary = (strcmp(result->file_type, "Text File") != 0 && 
                     strstr(result->file_type, "Image") == NULL);
    
    /* Scan for patterns */
    scan_patterns((char*)content, file_size, result, is_binary);
    
    /* Calculate risk */
    calculate_risk_score(result);
    
    result->analysis_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    
    free(content);
    return 0;
}

/*
 * Print result
 */
void print_result(analysis_result_t* result) {
    printf("\n=== File Analysis Result ===\n");
    printf("File: %s\n", result->filename);
    printf("Size: %llu bytes\n", (unsigned long long)result->file_size);
    printf("Type: %s\n", result->file_type);
    printf("Risk Score: %d/100\n", result->risk_score);
    printf("Risk Level: %s\n", result->risk_level);
    printf("Findings: %d\n", result->finding_count);
    printf("Analysis Time: %.3f seconds\n", result->analysis_time);
    
    if (result->finding_count > 0) {
        printf("\n=== Findings ===\n");
        for (int i = 0; i < result->finding_count && i < 20; i++) {
            finding_t* f = &result->findings[i];
            printf("[%s] %s at line %d (risk: %d)\n", 
                   f->risk >= RISK_HIGH ? "!" : "*",
                   f->pattern_name, f->line_number, f->risk);
        }
        if (result->finding_count > 20) {
            printf("... and %d more findings\n", result->finding_count - 20);
        }
    }
}

/*
 * Export JSON
 */
int export_json(const char* filename, analysis_result_t* result) {
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"filename\": \"%s\",\n", result->filename);
    fprintf(fp, "  \"file_size\": %llu,\n", (unsigned long long)result->file_size);
    fprintf(fp, "  \"file_type\": \"%s\",\n", result->file_type);
    fprintf(fp, "  \"risk_score\": %d,\n", result->risk_score);
    fprintf(fp, "  \"risk_level\": \"%s\",\n", result->risk_level);
    fprintf(fp, "  \"finding_count\": %d,\n", result->finding_count);
    fprintf(fp, "  \"analysis_time\": %.3f,\n", result->analysis_time);
    fprintf(fp, "  \"findings\": [\n");
    
    for (int i = 0; i < result->finding_count; i++) {
        finding_t* f = &result->findings[i];
        fprintf(fp, "    {\"pattern\": \"%s\", \"line\": %d, \"risk\": %d}%s\n",
                f->pattern_name, f->line_number, f->risk,
                (i < result->finding_count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    return 0;
}

/*
 * Main
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("File Analyzer - Pure C Implementation\n");
        printf("Usage: %s <file> [output.json]\n", argv[0]);
        printf("Example: %s suspicious.exe analysis.json\n", argv[0]);
        return 1;
    }
    
    const char* input = argv[1];
    const char* output = (argc > 2) ? argv[2] : NULL;
    
    printf("\n=== File Analyzer ===\n");
    printf("[*] Analyzing: %s\n", input);
    
    analysis_result_t result;
    if (analyze_file(input, &result) < 0) {
        return 1;
    }
    
    print_result(&result);
    
    if (output) {
        export_json(output, &result);
        printf("\n[*] Results exported to: %s\n", output);
    }
    
    /* Return non-zero if high risk */
    return (result.risk_score >= 50) ? 1 : 0;
}
