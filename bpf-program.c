// bpf_program.c
// BPF program for tracking Java library/method usage and identifying vulnerabilities

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

// Maximum stack depth to capture
#define MAX_STACK_DEPTH 127

// Target process ID to monitor (set from user space)
const volatile __u32 target_pid = 0;

// Struct to identify unique stack traces
struct stack_key {
    __u32 pid;
    __s32 user_stack_id;
};

// Maps to store stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

// Map to count stack trace occurrences
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct stack_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} counts SEC(".maps");

// Trace method execution
SEC("perf_event")
int trace_method_execution(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    
    // Skip if not our target process
    if (tgid != target_pid)
        return 0;
        
    // Get user space stack trace
    struct stack_key key = {0};
    key.pid = tgid;
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    if (key.user_stack_id >= 0) {
        // Increment counter for this stack
        __u64 *count, zero = 0;
        count = bpf_map_lookup_elem(&counts, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            bpf_map_update_elem(&counts, &key, &zero, BPF_ANY);
        }
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
