// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define FNAME_LEN 256
#define MAX_FDS 6

struct event {
        __u32 pid;
        char comm[TASK_COMM_LEN];
        char fname[FNAME_LEN];
        char syscall[16];
        __s32 fds[MAX_FDS];
        __u32 nfds;
};

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

/* Map para correlacionar enter->exit com filenames (open/openat/creat) */
struct fname_val {
        char fname[FNAME_LEN];
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16384);
        __type(key, __u64);
        __type(value, struct fname_val);
} fname_map SEC(".maps");

/* Map para correlacionar enter->exit para pipe/pipe2 (guarda ponteiro do array
 * user) */
struct pipe_arg {
        __u64 user_ptr;
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, __u64);
        __type(value, struct pipe_arg);
} pipe_map SEC(".maps");

static __always_inline void init_event(struct event *e) {
    __builtin_memset(e, 0, sizeof(*e));
    e->nfds = 0;
    e->fds[0] = -1;
}

static __always_inline void submit_event(const struct event *tmp) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memcpy(e, tmp, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
}

/* =============================
   ENTER: guarda filename para open/openat/creat
   ============================= */

/* open (enter) - args[0] = filename */
SEC("tracepoint/syscalls/sys_enter_open")
int te_enter_open(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];
    __u64 id = bpf_get_current_pid_tgid();

    struct fname_val val = {};
    if (bpf_probe_read_user_str(&val.fname, sizeof(val.fname), filename) <= 0) {
        // leitura falhou -> não inserir
        return 0;
    }

    // store filename keyed by pidtgid
    bpf_map_update_elem(&fname_map, &id, &val, BPF_ANY);
    return 0;
}

/* openat (enter) - args[1] = filename */
SEC("tracepoint/syscalls/sys_enter_openat")
int te_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    __u64 id = bpf_get_current_pid_tgid();

    struct fname_val val = {};
    if (bpf_probe_read_user_str(&val.fname, sizeof(val.fname), filename) <= 0) {
        return 0;
    }
    bpf_map_update_elem(&fname_map, &id, &val, BPF_ANY);
    return 0;
}

/* creat (enter) - args[0] = filename */
SEC("tracepoint/syscalls/sys_enter_creat")
int te_enter_creat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];
    __u64 id = bpf_get_current_pid_tgid();

    struct fname_val val = {};
    if (bpf_probe_read_user_str(&val.fname, sizeof(val.fname), filename) <= 0) {
        return 0;
    }
    bpf_map_update_elem(&fname_map, &id, &val, BPF_ANY);
    return 0;
}

/* =============================
   ENTER: guarda ponteiro para pipe/pipe2 (array user) para ler no exit
   ============================= */

/* pipe (enter) - args[0] = int __user *pipefd */
SEC("tracepoint/syscalls/sys_enter_pipe")
int te_enter_pipe(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ptr = (unsigned long)ctx->args[0];

    if (ptr == 0)
        return 0;

    struct pipe_arg p = {};
    p.user_ptr = ptr;
    bpf_map_update_elem(&pipe_map, &id, &p, BPF_ANY);
    return 0;
}

/* pipe2 (enter) - args[0] = int __user *pipefd, args[1] = flags */
SEC("tracepoint/syscalls/sys_enter_pipe2")
int te_enter_pipe2(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ptr = (unsigned long)ctx->args[0];

    if (ptr == 0)
        return 0;

    struct pipe_arg p = {};
    p.user_ptr = ptr;
    bpf_map_update_elem(&pipe_map, &id, &p, BPF_ANY);
    return 0;
}

/* =============================
   EXIT: open/openat/creat -> pega ret (fd) e correlaciona com filename do map
   ============================= */

SEC("tracepoint/syscalls/sys_exit_open")
int te_exit_open(struct trace_event_raw_sys_exit *ctx) {
    int ret = (int)ctx->ret;
    __u64 id = bpf_get_current_pid_tgid();

    struct fname_val *v = bpf_map_lookup_elem(&fname_map, &id);
    struct event tmp;
    init_event(&tmp);

    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "open", 5);

    if (v) {
        // copy fname from map into event
        __builtin_memcpy(&tmp.fname, v->fname, sizeof(tmp.fname));
        // remove map entry
        bpf_map_delete_elem(&fname_map, &id);
    } else {
        tmp.fname[0] = '\0';
    }

    if (ret >= 0) {
        tmp.nfds = 1;
        tmp.fds[0] = ret;
    } else {
        tmp.nfds = 0;
        tmp.fds[0] = -1;
    }

    submit_event(&tmp);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int te_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    int ret = (int)ctx->ret;
    __u64 id = bpf_get_current_pid_tgid();

    struct fname_val *v = bpf_map_lookup_elem(&fname_map, &id);
    struct event tmp;
    init_event(&tmp);

    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "openat", 7);

    if (v) {
        __builtin_memcpy(&tmp.fname, v->fname, sizeof(tmp.fname));
        bpf_map_delete_elem(&fname_map, &id);
    } else {
        tmp.fname[0] = '\0';
    }

    if (ret >= 0) {
        tmp.nfds = 1;
        tmp.fds[0] = ret;
    } else {
        tmp.nfds = 0;
        tmp.fds[0] = -1;
    }

    submit_event(&tmp);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int te_exit_creat(struct trace_event_raw_sys_exit *ctx) {
    int ret = (int)ctx->ret;
    __u64 id = bpf_get_current_pid_tgid();

    struct fname_val *v = bpf_map_lookup_elem(&fname_map, &id);
    struct event tmp;
    init_event(&tmp);

    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "creat", 6);

    if (v) {
        __builtin_memcpy(&tmp.fname, v->fname, sizeof(tmp.fname));
        bpf_map_delete_elem(&fname_map, &id);
    } else {
        tmp.fname[0] = '\0';
    }

    if (ret >= 0) {
        tmp.nfds = 1;
        tmp.fds[0] = ret;
    } else {
        tmp.nfds = 0;
        tmp.fds[0] = -1;
    }

    submit_event(&tmp);
    return 0;
}

/* =============================
   EXIT: pipe/pipe2 -> ler array de FDs preenchido em userland
   ============================= */

SEC("tracepoint/syscalls/sys_exit_pipe")
int te_exit_pipe(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct pipe_arg *p = bpf_map_lookup_elem(&pipe_map, &id);
    if (!p)
        return 0;

    struct event tmp;
    init_event(&tmp);

    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "pipe", 5);

    // try to read two ints from user memory at p->user_ptr
    int fds_arr[2] = {-1, -1};
    // read first
    if (bpf_probe_read_user(&fds_arr[0], sizeof(int),
                            (void *)(unsigned long)p->user_ptr) < 0) {
        // failed; send with nfds = 0
        tmp.nfds = 0;
        tmp.fds[0] = -1;
    } else {
        // read second (pointer + sizeof(int))
        if (bpf_probe_read_user(
                &fds_arr[1], sizeof(int),
                (void *)(unsigned long)(p->user_ptr + sizeof(int))) < 0) {
            // second failed; still send first
            tmp.nfds = 1;
            tmp.fds[0] = fds_arr[0];
        } else {
            tmp.nfds = 2;
            tmp.fds[0] = fds_arr[0];
            tmp.fds[1] = fds_arr[1];
        }
    }

    // cleanup map
    bpf_map_delete_elem(&pipe_map, &id);

    submit_event(&tmp);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe2")
int te_exit_pipe2(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct pipe_arg *p = bpf_map_lookup_elem(&pipe_map, &id);
    if (!p)
        return 0;

    struct event tmp;
    init_event(&tmp);

    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "pipe2", 6);

    int fds_arr[2] = {-1, -1};
    if (bpf_probe_read_user(&fds_arr[0], sizeof(int),
                            (void *)(unsigned long)p->user_ptr) < 0) {
        tmp.nfds = 0;
        tmp.fds[0] = -1;
    } else {
        if (bpf_probe_read_user(
                &fds_arr[1], sizeof(int),
                (void *)(unsigned long)(p->user_ptr + sizeof(int))) < 0) {
            tmp.nfds = 1;
            tmp.fds[0] = fds_arr[0];
        } else {
            tmp.nfds = 2;
            tmp.fds[0] = fds_arr[0];
            tmp.fds[1] = fds_arr[1];
        }
    }

    bpf_map_delete_elem(&pipe_map, &id);

    submit_event(&tmp);
    return 0;
}

/* =============================
   Exemplos: sys_enter para operações que usam FD diretamente (já tinha no seu
   código) (read/write/close/ftruncate/fsync etc)
   ============================= */

/* write (enter) */
SEC("tracepoint/syscalls/sys_enter_write")
int te_enter_write(struct trace_event_raw_sys_enter *ctx) {
    struct event tmp;
    init_event(&tmp);

    __u64 id = bpf_get_current_pid_tgid();
    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "write", 6);

    long fd = (long)ctx->args[0];
    tmp.nfds = 1;
    tmp.fds[0] = (fd >= 0) ? (__s32)fd : -1;

    submit_event(&tmp);
    return 0;
}

/* read (enter) */
SEC("tracepoint/syscalls/sys_enter_read")
int te_enter_read(struct trace_event_raw_sys_enter *ctx) {
    struct event tmp;
    init_event(&tmp);

    __u64 id = bpf_get_current_pid_tgid();
    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "read", 5);

    long fd = (long)ctx->args[0];
    tmp.nfds = 1;
    tmp.fds[0] = (fd >= 0) ? (__s32)fd : -1;

    submit_event(&tmp);
    return 0;
}

/* close (enter) */
SEC("tracepoint/syscalls/sys_enter_close")
int te_enter_close(struct trace_event_raw_sys_enter *ctx) {
    struct event tmp;
    init_event(&tmp);

    __u64 id = bpf_get_current_pid_tgid();
    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "close", 6);

    long fd = (long)ctx->args[0];
    tmp.nfds = 1;
    tmp.fds[0] = (fd >= 0) ? (__s32)fd : -1;

    submit_event(&tmp);
    return 0;
}

/* unlink (enter) - path-based */
SEC("tracepoint/syscalls/sys_enter_unlink")
int te_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];
    struct event tmp;
    init_event(&tmp);

    __u64 id = bpf_get_current_pid_tgid();
    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "unlink", 7);

    if (bpf_probe_read_user_str(&tmp.fname, sizeof(tmp.fname), filename) > 0) {
        tmp.nfds = 0;
        tmp.fds[0] = -1;
        submit_event(&tmp);
    }
    return 0;
}

/* rename (enter) */
SEC("tracepoint/syscalls/sys_enter_rename")
int te_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    const char *oldname = (const char *)ctx->args[0];
    struct event tmp;
    init_event(&tmp);

    __u64 id = bpf_get_current_pid_tgid();
    tmp.pid = (__u32)(id >> 32);
    bpf_get_current_comm(&tmp.comm, sizeof(tmp.comm));
    __builtin_memcpy(tmp.syscall, "rename", 7);

    if (bpf_probe_read_user_str(&tmp.fname, sizeof(tmp.fname), oldname) > 0) {
        tmp.nfds = 0;
        tmp.fds[0] = -1;
        submit_event(&tmp);
    }
    return 0;
}

/* Outros path-based (mkdir, rmdir, chmod, chown, truncate) podem ser
 * adicionados de forma similar. */

/* =============================
   End
   ============================= */

char LICENSE[] SEC("license") = "GPL";
