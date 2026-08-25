// execve_trace.c
//
// eBPF kprobes that intercept execve(), tcp_connect(), and vfs_write()
// and report events for the calling process.
//
// All hooks support optional PID filtering via a BPF map set from
// user space: if a target PID is set and non-zero, only events from
// that PID are reported.
//
// The tcp_connect hook exposes the destination IPv4 address for
// controller-side policy evaluation.
//
// Kernel-level blocking (-EPERM) is intentionally not implemented yet.

#include <linux/in.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_ARRAY(target_pid_map, u32, 1);

struct sockaddr_in_kg {
    short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char pad[8];
};

struct qstr {
    const unsigned char* name;
    unsigned int hash_len;
};

struct path {
    void* mnt;
    void* dentry;
};

struct file {
    void* f_op;
    void* f_mode;
    void* f_pos;
    struct path f_path;
};

struct dentry {
    unsigned char pad[40];
    struct qstr d_name;
};

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

    bpf_get_current_comm(
        &comm,
        sizeof(comm));

    bpf_trace_printk(
        "execve called by PID %d (%s)\n",
        pid,
        comm);

    return 0;
}

int trace_tcp_connect(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_target_pid(pid)) {
        return 0;
    }

    struct sockaddr_in_kg addr = { };
    void* user_addr = (void*)PT_REGS_PARM2(ctx);

    if (user_addr == NULL) {
        return 0;
    }

    bpf_probe_read_user(
        &addr,
        sizeof(addr),
        user_addr);

    u32 ip = addr.sin_addr;

    /*
     * bpf_trace_printk() in this environment supports
     * only a limited number of arguments/conversion specifiers.
     *
     * Print the IPv4 address as one 32-bit integer.
     * The controller can convert it to dotted-decimal form.
     */
    bpf_trace_printk(
        "tcp_connect ip=%u\n",
        ip);

    return 0;
}

int trace_vfs_write(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_target_pid(pid)) {
        return 0;
    }

    struct file* file = (struct file*)PT_REGS_PARM1(ctx);

    if (file == NULL) {
        return 0;
    }

    struct path path;
    struct dentry dentry;
    struct qstr name;

    bpf_probe_read_kernel(
        &path,
        sizeof(path),
        &file->f_path);

    if (path.dentry == NULL) {
        return 0;
    }

    bpf_probe_read_kernel(
        &dentry,
        sizeof(dentry),
        path.dentry);

    bpf_probe_read_kernel(
        &name,
        sizeof(name),
        &dentry.d_name);

    if (name.name == NULL) {
        return 0;
    }

    char filename[128];

    bpf_probe_read_kernel_str(
        filename,
        sizeof(filename),
        name.name);

    bpf_trace_printk(
        "vfs_write PID %d: %s\n",
        pid,
        filename);

    return 0;
}
