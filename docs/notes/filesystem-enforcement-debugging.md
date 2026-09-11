# Deep Dive: Filesystem LSM Enforcement & eBPF Debugging Journey

This document details the complete investigative process, root causes, kernel memory discoveries, and engineering fixes that resolved KernelGuard's filesystem enforcement accuracy and dynamic file lifecycle handling.

---

## 1. Problem Statement & Symptoms

During the Day 6 / Day 7 enforcement audit (`tests/test_enforcement_audit.py`), network blocking (`-EPERM`) and PID isolation performed as expected. However, filesystem enforcement exhibited persistent failures:

```text
--- Filesystem Enforcement Audit ---
Writing to ALLOWED file (/tmp/kernelguard-test.txt)...
❌ FAIL: Allowed file write was incorrectly blocked (EPERM)!
Writing to DENIED file (/tmp/kernelguard-unauthorized.txt)...
✅ SUCCESS: Denied file write correctly blocked with EPERM.
```

Even after verifying that `/tmp/kernelguard-test.txt` was declared in `policy.json`, allowed file writes were denied with `EPERM`.

---

## 2. Core Technical Roadblocks Identified

An end-to-end investigation revealed four interdependent layers of failure:

1. **Static Inode vs. Dynamic File Creation**:
   - Initial versions resolved paths to `(dev, ino)` pairs *only once* at daemon startup.
   - If a file did not exist before KernelGuard started, or if an existing file was truncated, recreated, or replaced (e.g. atomic write via temporary file rename), its new inode did not exist in the BPF allowlist and was blocked.

2. **Kernel Struct Memory Alignment in eBPF**:
   - Directly including `<linux/fs.h>` inside the eBPF C program causes BCC compilation errors on modern Linux kernels due to conflicts with userspace libc headers.
   - Manual compatibility structs were used, but their field offsets were guessed or based on older kernel versions rather than the host Linux 6.x kernel.

3. **Kernel `dev_t` Size & Memory Overwrite Bug**:
   - In Linux kernel space, `dev_t` in `struct super_block` is a **32-bit unsigned int** (`u32`), whereas the BPF map key used a 64-bit integer (`u64 dev`).
   - `bpf_probe_read_kernel(&key.dev, sizeof(key.dev), &sb->s_dev)` read **8 bytes** from a **4-byte field**, overwriting the top 32 bits of `key.dev` with garbage kernel memory.

4. **Userspace (Glibc) vs. Kernel `dev_t` Bit Encoding**:
   - Glibc's `stat.st_dev` encodes device numbers using GNU bit-twiddling that differs from the kernel's native `(major << 20) | minor` representation on disks with non-zero major numbers (e.g. root filesystems on NVMe / SCSI).

---

## 3. Step-by-Step Resolution

### 3.1 Multi-Tier BPF Allowlist Architecture

To support dynamic file creation and atomic replacement without sacrificing security, three BPF hash maps were introduced:

1. `filesystem_allowed_map`: Exact `(dev, ino)` lookup.
2. `filesystem_allowed_parent_map`: Directory `(dev, dir_ino)` for directory-level allowances.
3. `filesystem_allowed_name_map`: `(dev, parent_ino, name_hash)` composite key.

**Dynamic Promotion:**
When an unmapped file is written to:
1. KernelGuard reads the parent dentry's `(dev, parent_ino)`.
2. Hashes the filename using a fast 64-bit djb2 hash.
3. Checks `filesystem_allowed_name_map`.
4. If matched, the newly created file's exact `(dev, ino)` is automatically inserted into `filesystem_allowed_map`, accelerating subsequent writes to $O(1)$.

### 3.2 Extracting Exact Kernel Memory Offsets

Because header inclusion was prohibited by BCC build constraints, we used Clang type-checking introspection to query the exact struct offsets from the live kernel compiler:

```c
char (*f_path)[__builtin_offsetof(struct file, f_path)] = 1;
char (*f_inode)[__builtin_offsetof(struct file, f_inode)] = 1;
char (*d_parent)[__builtin_offsetof(struct dentry, d_parent)] = 1;
char (*d_name)[__builtin_offsetof(struct dentry, d_name)] = 1;
char (*d_inode)[__builtin_offsetof(struct dentry, d_inode)] = 1;
char (*q_name)[__builtin_offsetof(struct qstr, name)] = 1;
char (*i_sb)[__builtin_offsetof(struct inode, i_sb)] = 1;
char (*i_ino)[__builtin_offsetof(struct inode, i_ino)] = 1;
char (*s_dev)[__builtin_offsetof(struct super_block, s_dev)] = 1;
```

When compiled, Clang errors out and prints the exact array dimensions matching the byte offsets:

| Structure | Field | Expected / Old | Live Kernel (Linux 6.x) | Consequence of Mismatch |
|---|---|---|---|---|
| `struct file` | `f_inode` | +32 | **+32** | Matched |
| `struct file` | `f_path` | +16 | **+64** | eBPF read path from invalid offset (+16), corrupting `dentry` |
| `struct path` | `dentry` | +8 | **+8** | Matched |
| `struct dentry` | `d_parent` | +24 | **+24** | Matched |
| `struct dentry` | `d_name` | +32 | **+32** | Matched |
| `struct dentry` | `d_inode` | +48 | **+48** | Matched |
| `struct qstr` | `name` | +0 | **+8** | In Linux 6.x, `hash_len` (8 bytes) is first; `name` is second. eBPF was treating the hash as a memory pointer! |
| `struct inode` | `i_mode` | +0 | **+0** | Matched |
| `struct inode` | `i_sb` | +40 | **+40** | Matched |
| `struct inode` | `i_ino` | +64 | **+64** | Matched |
| `struct super_block` | `s_dev` | +16 | **+16** | Matched |

#### Struct Corrections in `ebpf/execve_trace.c`

```c
struct qstr {
    char pad[8];               // hash_len is at +0
    const unsigned char* name; // name is at +8
};

struct file {
    char pad1[32];
    struct kg_inode* f_inode; // at +32
    char pad2[24];            // 32 + 8 + 24 = 64
    struct path f_path;       // at +64
};

struct dentry {
    unsigned char pad1[24];
    void* d_parent;           // at +24
    struct qstr d_name;       // at +32 (16 bytes)
    void* d_inode;            // at +48
};
```

### 3.3 Fixing the `dev_t` 32-bit Memory Overwrite

In `ebpf/execve_trace.c`, `s_dev` is 4 bytes. Reading 8 bytes pulled in adjacent memory:

```c
// BUG: Read 8 bytes into 4-byte s_dev field
bpf_probe_read_kernel(&key.dev, sizeof(key.dev), &sb->s_dev);

// FIX: Read exactly 4 bytes into u32, then assign to u64
u32 file_dev = 0;
bpf_probe_read_kernel(&file_dev, sizeof(file_dev), &sb->s_dev);
key.dev = (u64)file_dev;
```

### 3.4 Cross-Filesystem Device Number Normalization

In `kernelguard/controller.py`, glibc's `stat().st_dev` was converted into the kernel's native representation:

```python
@staticmethod
def _encode_dev(st_dev: int) -> int:
    """Convert userspace/glibc st_dev to Linux kernel dev_t format."""
    major = os.major(st_dev)
    minor = os.minor(st_dev)
    return (major << 20) | minor
```

---

## 4. Final Verification & Audit Results

Running `tests/test_enforcement_audit.py` with KernelGuard active:

```text
--- Network Enforcement Audit ---
Connecting to ALLOWED IP (1.1.1.1)...
✅ SUCCESS: Allowed connection was NOT blocked by EPERM.
Connecting to DENIED IP (10.0.0.1)...
✅ SUCCESS: Denied connection correctly blocked with EPERM.

--- Filesystem Enforcement Audit ---
Waiting a brief moment so you can confirm KernelGuard is running...
Writing to ALLOWED file (/tmp/kernelguard-test.txt)...
✅ SUCCESS: Allowed file write was NOT blocked.
Writing to DENIED file (/tmp/kernelguard-unauthorized.txt)...
✅ SUCCESS: Denied file write correctly blocked with EPERM.

--- PID Isolation Audit ---
Spawning a subprocess to test if it gets blocked (it shouldn't be)...
✅ SUCCESS: Subprocess network connection was NOT blocked by EPERM.
✅ SUCCESS: Subprocess file write was NOT blocked by EPERM.

Enforcement audit complete.
```

All 12 unit tests in `tests/` pass with zero regressions.
Kernel-level security enforcement is verified operational and resilient to dynamic file creation.
