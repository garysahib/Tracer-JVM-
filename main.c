// main.c - Simplified Java Vulnerability Tracker
// Usage: sudo ./java-vuln-tracker -p <JAVA_PID> -V vulns.json

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <json-c/json.h>
#include "bpf_skel.h"

#define MAX_SYMBOL_LEN 256
#define MAX_LIBRARIES 1024
#define MAX_METHODS 4096
#define MAX_VULNS 1024
#define SAMPLE_HZ 10  // Default sampling rate
#define DEFAULT_DURATION 60  // Default run duration

struct vulnerability {
    char package[MAX_SYMBOL_LEN];
    char version[64];
    char method[MAX_SYMBOL_LEN];
    char cve_id[32];
    char description[256];
    int severity;
};

struct library_info {
    char name[MAX_SYMBOL_LEN];
    char version[64];
    unsigned long count;
    bool vulnerable;
    char cve_id[32];
    int severity;
};

struct method_info {
    char name[MAX_SYMBOL_LEN];
    unsigned long count;
    bool vulnerable;
    char cve_id[32];
    int severity;
};

// Global state
static struct vulnerability vulns[MAX_VULNS];
static int num_vulns = 0;
static struct library_info libraries[MAX_LIBRARIES];
static int num_libraries = 0;
static struct method_info methods[MAX_METHODS];
static int num_methods = 0;
static bool verbose = false;
static volatile bool exiting = false;
static pid_t target_pid = -1;

// Function declarations
static void sig_handler(int sig);
static int load_vulns(const char *filename);
static int setup_bpf(struct bpf_program_bpf **skel, pid_t pid);
static char* detect_version(const char *package);
static bool check_vulnerability(const char *lib, const char *method, char *cve, int *severity);
static void track_library(const char *lib, const char *method);
static void track_method(const char *method);
static void process_stack(uint64_t *stack, int depth);
static void print_results(FILE *out);

// Signal handler for graceful exit
static void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct bpf_program_bpf *skel = NULL;
    int opt, err, duration = DEFAULT_DURATION;
    FILE *output = stdout;
    char *vuln_file = NULL;
    int c;
    
    // Parse command line options
    while ((c = getopt(argc, argv, "p:d:o:V:vh")) != -1) {
        switch (c) {
        case 'p':
            target_pid = atoi(optarg);
            break;
        case 'd':
            duration = atoi(optarg);
            break;
        case 'o':
            output = fopen(optarg, "w");
            if (!output) {
                fprintf(stderr, "Failed to open output file: %s\n", optarg);
                return 1;
            }
            break;
        case 'V':
            vuln_file = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s -p <pid> [-d seconds] [-o output.json] [-V vulns.json] [-v]\n", argv[0]);
            return c == 'h' ? 0 : 1;
        }
    }
    
    // Validate required arguments
    if (target_pid <= 0) {
        fprintf(stderr, "Error: Must specify Java process ID with -p\n");
        return 1;
    }
    
    // Load vulnerability database if provided
    if (vuln_file) {
        if (load_vulns(vuln_file) < 0) {
            fprintf(stderr, "Warning: Failed to load vulnerability database\n");
        }
    }
    
    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Setup BPF
    err = setup_bpf(&skel, target_pid);
    if (err) {
        fprintf(stderr, "Failed to setup BPF: %d\n", err);
        return 1;
    }
    
    // Generate Java symbol maps
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "create-java-perf-map.sh %d >/dev/null 2>&1", target_pid);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Could not generate Java symbol map\n");
    }
    
    printf("Monitoring Java process %d for %d seconds... Press Ctrl+C to stop.\n", target_pid, duration);
    
    // Main monitoring loop
    time_t start = time(NULL);
    while (!exiting && (time(NULL) - start < duration)) {
        // Sleep and periodically process stack traces
        sleep(1);
        
        // Process BPF data
        int stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
        int counts_map_fd = bpf_map__fd(skel->maps.counts);
        
        // Get stack traces (code that processes stack traces)
        // For simplicity, detailed implementation omitted
        
        // Every 5 seconds, print progress
        if (verbose && (time(NULL) - start) % 5 == 0) {
            fprintf(stderr, "Progress: %d libraries, %d methods tracked\n", 
                   num_libraries, num_methods);
        }
    }
    
    // Print results
    print_results(output);
    
    // Cleanup
    bpf_program_bpf__destroy(skel);
    if (output != stdout)
        fclose(output);
        
    printf("Completed monitoring. Found %d libraries and %d methods.\n", 
           num_libraries, num_methods);
           
    return 0;
}

// Load vulnerability database
static int load_vulns(const char *filename) {
    struct json_object *root, *vulns_array, *vuln;
    
    // Load and parse JSON
    root = json_object_from_file(filename);
    if (!root) {
        fprintf(stderr, "Error: Failed to parse %s\n", filename);
        return -1;
    }
    
    // Get vulnerabilities array
    if (!json_object_object_get_ex(root, "vulnerabilities", &vulns_array)) {
        fprintf(stderr, "Error: Missing 'vulnerabilities' array in JSON\n");
        json_object_put(root);
        return -1;
    }
    
    // Process each vulnerability
    int count = json_object_array_length(vulns_array);
    for (int i = 0; i < count && num_vulns < MAX_VULNS; i++) {
        struct json_object *package, *version, *cve, *method, *desc, *severity;
        vuln = json_object_array_get_idx(vulns_array, i);
        
        // Get required fields
        if (!json_object_object_get_ex(vuln, "package", &package) ||
            !json_object_object_get_ex(vuln, "version", &version) ||
            !json_object_object_get_ex(vuln, "cve", &cve)) {
            continue;
        }
        
        // Store vulnerability info
        strncpy(vulns[num_vulns].package, json_object_get_string(package), MAX_SYMBOL_LEN-1);
        strncpy(vulns[num_vulns].version, json_object_get_string(version), 63);
        strncpy(vulns[num_vulns].cve_id, json_object_get_string(cve), 31);
        
        // Optional fields
        if (json_object_object_get_ex(vuln, "method", &method)) {
            strncpy(vulns[num_vulns].method, json_object_get_string(method), MAX_SYMBOL_LEN-1);
        }
        
        if (json_object_object_get_ex(vuln, "description", &desc)) {
            strncpy(vulns[num_vulns].description, json_object_get_string(desc), 255);
        } else {
            strcpy(vulns[num_vulns].description, "No description available");
        }
        
        if (json_object_object_get_ex(vuln, "severity", &severity)) {
            vulns[num_vulns].severity = json_object_get_int(severity);
        } else {
            vulns[num_vulns].severity = 5; // Default medium severity
        }
        
        num_vulns++;
    }
    
    json_object_put(root);
    printf("Loaded %d vulnerabilities\n", num_vulns);
    return 0;
}

// Setup BPF program
static int setup_bpf(struct bpf_program_bpf **skel, pid_t pid) {
    struct bpf_program_bpf *s;
    int err;
    
    // Set higher rlimit to allow BPF maps
    struct rlimit rlim = {
        .rlim_cur = 128UL << 20, // 128 MB
        .rlim_max = 128UL << 20,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    // Open BPF skeleton
    s = bpf_program_bpf__open();
    if (!s) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }
    
    // Set target PID
    s->rodata->target_pid = pid;
    
    // Load & verify BPF program
    err = bpf_program_bpf__load(s);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        bpf_program_bpf__destroy(s);
        return -1;
    }
    
    // Attach perf event
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_CPU_CLOCK,
        .sample_freq = SAMPLE_HZ,
        .freq = 1,
    };
    
    int pfd = perf_event_open(&attr, pid, -1, -1, 0);
    if (pfd < 0) {
        fprintf(stderr, "Failed to open perf event: %s\n", strerror(errno));
        bpf_program_bpf__destroy(s);
        return -1;
    }
    
    // Attach program to perf event
    s->links.trace_method_execution = 
        bpf_program__attach_perf_event(s->progs.trace_method_execution, pfd);
    if (!s->links.trace_method_execution) {
        close(pfd);
        bpf_program_bpf__destroy(s);
        return -1;
    }
    
    *skel = s;
    return 0;
}

// Track a library
static void track_library(const char *lib, const char *method) {
    if (!lib || !lib[0]) return;
    
    // Check if already tracked
    for (int i = 0; i < num_libraries; i++) {
        if (strcmp(libraries[i].name, lib) == 0) {
            libraries[i].count++;
            return;
        }
    }
    
    // Add new library if space available
    if (num_libraries < MAX_LIBRARIES) {
        char cve[32] = "";
        int severity = 0;
        
        // Check for vulnerability
        bool is_vulnerable = check_vulnerability(lib, method, cve, &severity);
        
        // Add to tracked libraries
        strncpy(libraries[num_libraries].name, lib, MAX_SYMBOL_LEN-1);
        strncpy(libraries[num_libraries].version, detect_version(lib), 63);
        libraries[num_libraries].count = 1;
        libraries[num_libraries].vulnerable = is_vulnerable;
        
        if (is_vulnerable) {
            strncpy(libraries[num_libraries].cve_id, cve, 31);
            libraries[num_libraries].severity = severity;
            
            // Alert on vulnerability
            fprintf(stderr, "\n!!! VULNERABILITY DETECTED !!!\n");
            fprintf(stderr, "Library: %s\n", lib);
            fprintf(stderr, "CVE: %s (Severity: %d/10)\n", cve, severity);
        }
        
        num_libraries++;
    }
}

// Track a method
static void track_method(const char *method) {
    if (!method || !method[0]) return;
    
    // Check if already tracked
    for (int i = 0; i < num_methods; i++) {
        if (strcmp(methods[i].name, method) == 0) {
            methods[i].count++;
            return;
        }
    }
    
    // Add new method if space available
    if (num_methods < MAX_METHODS) {
        // Extract package from method name
        char package[MAX_SYMBOL_LEN] = "";
        const char *lastdot = strrchr(method, '.');
        if (lastdot) {
            size_t len = lastdot - method;
            if (len < MAX_SYMBOL_LEN) {
                strncpy(package, method, len);
                package[len] = '\0';
            }
        }
        
        // Check for vulnerability
        char cve[32] = "";
        int severity = 0;
        bool is_vulnerable = check_vulnerability(package, method, cve, &severity);
        
        // Add to tracked methods
        strncpy(methods[num_methods].name, method, MAX_SYMBOL_LEN-1);
        methods[num_methods].count = 1;
        methods[num_methods].vulnerable = is_vulnerable;
        
        if (is_vulnerable) {
            strncpy(methods[num_methods].cve_id, cve, 31);
            methods[num_methods].severity = severity;
        }
        
        num_methods++;
    }
}

// Detect library version
static char* detect_version(const char *package) {
    static char version[64];
    strcpy(version, "unknown");
    
    // In production code, implement version detection from:
    // 1. classpath JARs
    // 2. META-INF/MANIFEST.MF files
    // 3. /proc/PID/maps data
    
    return version;
}

// Check if library or method is vulnerable
static bool check_vulnerability(const char *lib, const char *method, char *cve, int *severity) {
    if (num_vulns == 0 || !lib)
        return false;
    
    // Check each vulnerability
    for (int i = 0; i < num_vulns; i++) {
        if (strstr(lib, vulns[i].package)) {
            // If method-specific vulnerability
            if (vulns[i].method[0] && method) {
                if (strstr(method, vulns[i].method)) {
                    strncpy(cve, vulns[i].cve_id, 31);
                    *severity = vulns[i].severity;
                    return true;
                }
            } 
            // Whole package vulnerability
            else if (!vulns[i].method[0]) {
                strncpy(cve, vulns[i].cve_id, 31);
                *severity = vulns[i].severity;
                return true;
            }
        }
    }
    
    return false;
}

// Print results to output file
static void print_results(FILE *out) {
    fprintf(out, "{\n  \"summary\": {\n");
    fprintf(out, "    \"timestamp\": %ld,\n", time(NULL));
    fprintf(out, "    \"pid\": %d,\n", target_pid);
    fprintf(out, "    \"libraries_found\": %d,\n", num_libraries);
    fprintf(out, "    \"methods_found\": %d,\n", num_methods);
    fprintf(out, "    \"vulnerabilities_checked\": %d\n", num_vulns);
    fprintf(out, "  },\n");
    
    // Print libraries
    fprintf(out, "  \"libraries\": [\n");
    for (int i = 0; i < num_libraries; i++) {
        fprintf(out, "    {\n");
        fprintf(out, "      \"name\": \"%s\",\n", libraries[i].name);
        fprintf(out, "      \"version\": \"%s\",\n", libraries[i].version);
        fprintf(out, "      \"count\": %lu,\n", libraries[i].count);
        fprintf(out, "      \"vulnerable\": %s", libraries[i].vulnerable ? "true" : "false");
        
        if (libraries[i].vulnerable) {
            fprintf(out, ",\n      \"cve\": \"%s\",\n", libraries[i].cve_id);
            fprintf(out, "      \"severity\": %d", libraries[i].severity);
        }
        
        fprintf(out, "\n    }%s\n", (i < num_libraries - 1) ? "," : "");
    }
    fprintf(out, "  ],\n");
    
    // Print top methods
    fprintf(out, "  \"top_methods\": [\n");
    
    // Sort methods by count (simple bubble sort)
    for (int i = 0; i < num_methods - 1; i++) {
        for (int j = 0; j < num_methods - i - 1; j++) {
            if (methods[j].count < methods[j+1].count) {
                struct method_info temp = methods[j];
                methods[j] = methods[j+1];
                methods[j+1] = temp;
            }
        }
    }
    
    // Print sorted methods (top 50 or less)
    int count = (num_methods < 50) ? num_methods : 50;
    for (int i = 0; i < count; i++) {
        fprintf(out, "    {\n");
        fprintf(out, "      \"name\": \"%s\",\n", methods[i].name);
        fprintf(out, "      \"count\": %lu,\n", methods[i].count);
        fprintf(out, "      \"vulnerable\": %s", methods[i].vulnerable ? "true" : "false");
        
        if (methods[i].vulnerable) {
            fprintf(out, ",\n      \"cve\": \"%s\",\n", methods[i].cve_id);
            fprintf(out, "      \"severity\": %d", methods[i].severity);
        }
        
        fprintf(out, "\n    }%s\n", (i < count - 1) ? "," : "");
    }
    
    fprintf(out, "  ]\n}\n");
}
