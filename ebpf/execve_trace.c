// execve_trace.c
//
// KernelGuard eBPF hooks for execve(), tcp_connect(), and vfs_write(),
// plus BPF LSM enforcement hooks for network connections and file writes.
//
// Policy decisions are loaded from user space into BPF maps.
// PID filtering is shared by monitoring and enforcement.
//
// Active enforcement is opt-in from the controller. When enabled:
//   - IPv4 destinations not present in network_allowed_map are denied.
//   - file writes to inodes not present in filesystem_allowed_map are denied.
//   - denied operations return -EPERM from the BPF LSM hook.
//
// Kernel-level blocking is implemented through BPF LSM return values,
// rather than bpf_override_return(), because LSM hooks are designed to
// return an access-control decision directly.

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_ARRAY(target_pid_map, u32, 1);
BPF_ARRAY(enforcement_enabled, u32, 1);

BPF_HASH(network_allowed_map, u32, u8, 256);

struct filesystem_key {
    u64 dev;
    u64 ino;
};

BPF_HASH(filesystem_allowed_map, struct filesystem_key, u8, 1024);

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

static int enforcement_is_enabled(void)
{
    int key = 0;
    u32* enabled = enforcement_enabled.lookup(&key);

    return enabled != NULL && *enabled != 0;
}

static int is_network_allowed(u32 ip)
{
    u8* allowed = network_allowed_map.lookup(&ip);

    return allowed != NULL;
}

static int is_filesystem_allowed(struct filesystem_key* key)
{
    u8* allowed = filesystem_allowed_map.lookup(key);

    return allowed != NULL;
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
     * bpf_trace_printk() supports only a limited number of
     * conversion arguments in this environment.
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

/*
 * BPF LSM enforcement hook.
 *
 * The socket_connect LSM hook executes before the connection is
 * authorized. Returning -EPERM denies the operation.
 */
LSM_PROBE(socket_connect,
    struct socket* sock,
    struct sockaddr* address,
    int addrlen)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!enforcement_is_enabled() || !is_target_pid(pid)) {
        return 0;
    }

    if (address == NULL || addrlen < sizeof(struct sockaddr_in_kg)) {
        return 0;
    }

    struct sockaddr_in_kg addr = { };

    bpf_probe_read_kernel(
        &addr,
        sizeof(addr),
        address);

    if (addr.sin_family != AF_INET) {
        return 0;
    }

    if (is_network_allowed(addr.sin_addr)) {
        return 0;
    }

    bpf_trace_printk(
        "BLOCK tcp_connect ip=%u\n",
        addr.sin_addr);

    return -EPERM;
}

/*
 * BPF LSM enforcement hook for file permissions.
 *
 * The controller loads allowed (device, inode) pairs for the
 * configured filesystem paths. Only write access is enforced here.
 */
LSM_PROBE(file_permission,
    struct file* file,
    int mask)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!enforcement_is_enabled() || !is_target_pid(pid)) {
        return 0;
    }

    if (file == NULL || !(mask & MAY_WRITE)) {
        return 0;
    }

    struct inode* inode = NULL;
    struct super_block* sb = NULL;

    bpf_probe_read_kernel(
        &inode,
        sizeof(inode),
        &file->f_inode);

    if (inode == NULL) {
        return 0;
    }

    bpf_probe_read_kernel(
        &sb,
        sizeof(sb),
        &inode->i_sb);

    if (sb == NULL) {
        return 0;
    }

    struct filesystem_key key = { };

    bpf_probe_read_kernel(
        &key.ino,
        sizeof(key.ino),
        &inode->i_ino);

    bpf_probe_read_kernel(
        &key.dev,
        sizeof(key.dev),
        &sb->s_dev);

    if (is_filesystem_allowed(&key)) {
        return 0;
    }

    bpf_trace_printk(
        "BLOCK vfs_write PID %d\n",
        pid);

    return -EPERM;
}
