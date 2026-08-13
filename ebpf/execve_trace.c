// execve_trace.c
//
// Minimal eBPF kprobe that intercepts the execve() syscall and reports
// the PID and command name of the calling process.

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

int trace_execve(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_trace_printk("execve called by PID %d (%s)\n", pid, comm);

    return 0;
}
