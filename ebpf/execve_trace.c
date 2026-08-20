// execve_trace.c
//
// eBPF kprobes that intercept execve(), tcp_connect(), and vfs_write()
// and report the PID and command name of the calling process.
//
// All hooks support optional PID filtering via a BPF map set from
// user space: if a target PID is set and non-zero, only events from
// that PID are reported.

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_ARRAY(target_pid_map, u32, 1);

static int is_target_pid(u32 pid)
{
    int key = 0;
    u32* target_pid = target_pid_map.lookup(&key);

    if (target_pid != NULL && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    return 1;
}

int trace_execve(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_target_pid(pid)) {
        return 0;
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_trace_printk("execve called by PID %d (%s)\n", pid, comm);

    return 0;
}

int trace_tcp_connect(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_target_pid(pid)) {
        return 0;
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_trace_printk("tcp_connect called by PID %d (%s)\n", pid, comm);

    return 0;
}

int trace_vfs_write(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_target_pid(pid)) {
        return 0;
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_trace_printk("vfs_write called by PID %d (%s)\n", pid, comm);

    return 0;
}
