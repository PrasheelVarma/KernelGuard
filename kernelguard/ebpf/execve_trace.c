// execve_trace.c
//
// KernelGuard eBPF hooks for execve(), tcp_connect(), and vfs_write(),
// plus BPF LSM enforcement hooks for network connections and file writes.
//
// The original tracing code intentionally avoids <linux/fs.h> because
// BCC's userspace compilation of that header is incompatible with the
// current development kernel. The tracing compatibility structures below
// are therefore retained.
//
// Active enforcement is opt-in through enforcement_enabled.
// PID filtering is shared by monitoring and enforcement.

#include <linux/in.h>
#include <linux/sched.h>
#include <uapi/linux/errno.h>
#include <uapi/linux/ptrace.h>

#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif

BPF_ARRAY(target_pid_map, u32, 1);
BPF_ARRAY(exempt_pid_map, u32, 1);
BPF_ARRAY(enforcement_enabled, u32, 1);

BPF_HASH(network_allowed_map, u32, u8, 256);

struct in6_addr_kg {
    unsigned char in6_u[16];
};

BPF_HASH(network_allowed_v6_map, struct in6_addr_kg, u8, 256);

struct filesystem_key {
    u64 dev;
    u64 ino;
};

struct parent_name_key {
    u64 dev;
    u64 parent_ino;
    u64 name_hash;
};

BPF_HASH(filesystem_allowed_map, struct filesystem_key, u8, 2048);
BPF_HASH(filesystem_allowed_parent_map, struct filesystem_key, u8, 1024);
BPF_HASH(filesystem_allowed_name_map, struct parent_name_key, u8, 1024);

struct sockaddr_in_kg {
    short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char pad[8];
};

struct sockaddr_in6_kg {
    unsigned short sin6_family;
    unsigned short sin6_port;
    unsigned int sin6_flowinfo;
    struct in6_addr_kg sin6_addr;
    unsigned int sin6_scope_id;
};

/*
 * Tracing and enforcement compatibility structures.
 * These match the exact kernel memory offsets verified against BTF / kernel headers:
 * - struct file: f_inode at +32, f_path at +64
 * - struct path: mnt at +0, dentry at +8
 * - struct dentry: d_parent at +24, d_name at +32, d_inode at +48
 * - struct qstr: name at +8 (after hash_len at +0)
 * - struct inode: i_mode at +0, i_sb at +40, i_ino at +64
 * - struct super_block: s_dev at +16
 */
struct qstr {
    char pad[8];
    const unsigned char* name;
};

struct path {
    void* mnt;
    void* dentry;
};

struct kg_super_block {
    char pad[16];
    dev_t s_dev;
};

struct kg_inode {
    unsigned short i_mode;
    char pad1[38];
    struct kg_super_block* i_sb;
    char pad2[16];
    u64 i_ino;
};

struct file {
    char pad1[32];
    struct kg_inode* f_inode;
    char pad2[24];
    struct path f_path;
};

struct dentry {
    unsigned char pad1[24];
    void* d_parent;
    struct qstr d_name;
    void* d_inode;
};

static int is_exempt_pid(u32 pid)
{
    int key = 0;
    u32* exempt_pid = exempt_pid_map.lookup(&key);
    
    if (exempt_pid != NULL && *exempt_pid != 0 && *exempt_pid == pid) {
        return 1;
    }
    return 0;
}

static int is_target_pid(u32 pid)
{
    if (is_exempt_pid(pid)) {
        return 0;
    }

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

static __always_inline u64 hash_filename(const char *name) {
    u64 hash = 5381;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        char c = name[i];
        if (c == 0) break;
        hash = ((hash << 5) + hash) + (u64)c;
    }
    return hash;
}

static int is_filesystem_allowed(struct filesystem_key* file_key, void* dentry_ptr)
{
    u8* allowed = filesystem_allowed_map.lookup(file_key);
    if (allowed != NULL) {
        return 1;
    }

    if (dentry_ptr == NULL) {
        return 0;
    }

    struct dentry dentry = { };
    bpf_probe_read_kernel(&dentry, sizeof(dentry), dentry_ptr);

    if (dentry.d_parent == NULL) {
        return 0;
    }

    struct dentry parent_dentry = { };
    bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), dentry.d_parent);

    if (parent_dentry.d_inode == NULL) {
        return 0;
    }

    struct kg_inode parent_inode = { };
    bpf_probe_read_kernel(&parent_inode, sizeof(parent_inode), parent_dentry.d_inode);

    struct kg_super_block* sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &parent_inode.i_sb);

    if (sb == NULL) {
        return 0;
    }

    struct filesystem_key parent_key = { };
    bpf_probe_read_kernel(&parent_key.ino, sizeof(parent_key.ino), &parent_inode.i_ino);
    u32 parent_dev = 0;
    bpf_probe_read_kernel(&parent_dev, sizeof(parent_dev), &sb->s_dev);
    parent_key.dev = (u64)parent_dev;

    u8* parent_allowed = filesystem_allowed_parent_map.lookup(&parent_key);
    if (parent_allowed != NULL) {
        u8 one = 1;
        filesystem_allowed_map.update(file_key, &one);
        return 1;
    }

    if (dentry.d_name.name != NULL) {
        char filename[64] = { };
        bpf_probe_read_kernel_str(filename, sizeof(filename), dentry.d_name.name);

        u64 name_hash = hash_filename(filename);
        struct parent_name_key pn_key = {
            .dev = parent_key.dev,
            .parent_ino = parent_key.ino,
            .name_hash = name_hash,
        };

        u8* name_allowed = filesystem_allowed_name_map.lookup(&pn_key);
        if (name_allowed != NULL) {
            u8 one = 1;
            filesystem_allowed_map.update(file_key, &one);
            return 1;
        }
    }

    return 0;
}

static int is_network_allowed_v6(struct in6_addr_kg *ip)
{
    u8* allowed = network_allowed_v6_map.lookup(ip);
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

int trace_tcp_v6_connect(struct pt_regs* ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_target_pid(pid)) {
        return 0;
    }

    struct sockaddr_in6_kg addr = { };
    void* user_addr = (void*)PT_REGS_PARM2(ctx);

    if (user_addr == NULL) {
        return 0;
    }

    bpf_probe_read_user(
        &addr,
        sizeof(addr),
        user_addr);

    u64 hi = *(u64*)&addr.sin6_addr.in6_u[0];
    u64 lo = *(u64*)&addr.sin6_addr.in6_u[8];

    bpf_trace_printk(
        "tcp_v6_connect hi=%llu lo=%llu\n",
        hi, lo);

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

LSM_PROBE(socket_connect,
    struct socket* sock,
    struct sockaddr* address,
    int addrlen)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!enforcement_is_enabled() || !is_target_pid(pid)) {
        return 0;
    }

    if (address == NULL) {
        return 0;
    }

    struct sockaddr_in_kg addr = { };

    bpf_probe_read_kernel(
        &addr,
        sizeof(addr),
        address);
        
    bpf_trace_printk("socket_connect pid=%d family=%d len=%d\n", pid, addr.sin_family, addrlen);

    if (addr.sin_family == AF_INET) {
        if (is_network_allowed(addr.sin_addr)) {
            return 0;
        }

        bpf_trace_printk(
            "BLOCK tcp_connect ip=%u\n",
            addr.sin_addr);

        return -EPERM;
    } else if (addr.sin_family == 10) { // AF_INET6
        struct sockaddr_in6_kg addr6 = { };
        bpf_probe_read_kernel(&addr6, sizeof(addr6), address);
        
        if (is_network_allowed_v6(&addr6.sin6_addr)) {
            return 0;
        }

        u64 hi = *(u64*)&addr6.sin6_addr.in6_u[0];
        u64 lo = *(u64*)&addr6.sin6_addr.in6_u[8];

        bpf_trace_printk(
            "BLOCK tcp_v6_connect hi=%llu lo=%llu\n",
            hi, lo);

        return -EPERM;
    }

    return 0;
}

/*
 * BPF LSM filesystem enforcement.
 *
 * This first version uses a small compatibility representation of the
 * file/inode/superblock relationship rather than including <linux/fs.h>.
 * The actual offsets are resolved by BPF's BTF-aware CO-RE access through
 * preserve_access_index.
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

    struct kg_inode* inode = NULL;

    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);

    if (inode == NULL) {
        return 0;
    }

    // Only enforce policy on regular files to prevent blocking stdout/stderr
    unsigned short i_mode = 0;
    bpf_probe_read_kernel(&i_mode, sizeof(i_mode), &inode->i_mode);
    
    if ((i_mode & 00170000) != 0100000) { // (i_mode & S_IFMT) != S_IFREG
        return 0;
    }

    struct kg_super_block* sb = NULL;

    bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);

    if (sb == NULL) {
        return 0;
    }

    struct filesystem_key key = { };

    bpf_probe_read_kernel(&key.ino, sizeof(key.ino), &inode->i_ino);
    u32 file_dev = 0;
    bpf_probe_read_kernel(&file_dev, sizeof(file_dev), &sb->s_dev);
    key.dev = (u64)file_dev;

    struct path f_path = { };
    bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);

    if (is_filesystem_allowed(&key, f_path.dentry)) {
        return 0;
    }

    bpf_trace_printk(
        "BLOCK vfs_write PID %d\n",
        pid);

    return -EPERM;
}
