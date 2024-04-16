#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracing.bpf.h"

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

struct disk_span_t {
    struct span_base_t span_base;
    u32 dev;
    u32 exit_code;
    u32 recent_used_cpu;
    u8 op;
    u32 syscall_id;
    u32 span_name;
} ;

struct data_t {
    u64 starttime_ns;
    u32 counter;
    u32 syscall_id;
} __attribute__((packed));

struct exec_span_t {
    struct span_base_t span_base;
    char exe[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 10);
    __type(key, u32);
    __type(value, struct exec_span_t);
} traced_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct data_t);
} enter_id SEC(".maps");

#define submit_kamailio_span(map, type, rq, fill)                                                                      \
    struct span_parent_t parent = {};                                                                                  \
    parent.trace_id_hi = BPF_CORE_READ(rq, start_time_ns);                                                             \
    parent.trace_id_lo = (u64) rq;                                                                                     \
                                                                                                                       \
    submit_span(map, type, &parent, fill);

#define submit_kamailio_span_extra(map, type, ts, tgid, fill)                                                          \
    struct span_parent_t parent = {};                                                                                  \
    parent.trace_id_hi = ts;                                                                                           \
    parent.trace_id_lo = tgid;                                                                                         \
                                                                                                                       \
    submit_span(map, type, &parent, fill);

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024 * 64);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kamailio_service_spans SEC(".maps");

/*
// Clang 14 in Ubuntu 22.04 does not inline __builtin_memcmp, so we have to reimplement it.
static inline int memcmp_fallback(const void *str1, const void *str2, size_t count)
{
    const unsigned char *s1 = (const unsigned char *) str1;
    const unsigned char *s2 = (const unsigned char *) str2;

    while (count-- > 0) {
        if (*s1++ != *s2++)
            return s1[-1] < s2[-1] ? -1 : 1;
    }

    return 0;
}
*/

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    char comm[TASK_COMM_LEN];
    u64 timestamp = bpf_ktime_get_ns();
    struct data_t *ptr;
    struct task_struct *task;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    struct exec_span_t *exec_parent;
    struct exec_span_t exec_span = { 0 };

    task = bpf_get_current_task_btf();
    if (task->pid != pid)
        return 0;

    u64 tgid = task->tgid, ptgid = task->real_parent->tgid;

    // bpf_printk("raw_tracepoint_sys_enter task_struct: TGID: %d, PARENT: %d\n", tgid, ptgid);

    bpf_get_current_comm(&comm, sizeof(comm));
    int foundKamailio = 0;

    if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
        comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0') {
        foundKamailio = 1;
    }

    if (foundKamailio == 0) {
        return 1;
    }

    // u64 current_uid_gid = bpf_get_current_uid_gid();
    // u32 uid = current_uid_gid;
    unsigned long syscall_id = ctx->args[1];

    task = bpf_get_current_task_btf();
    if (task->pid != pid)
        return 0;

    if (ptgid == 1) {
        bpf_printk("raw_tracepoint_sys_enter: %s; GID: %d, ID:%u\n", comm, tgid, syscall_id);
    }

    // bpf_printk("raw_tracepoint_sys_enter task_struct: Time: %d, CPUTime: %d\n", task->start_time,
    // task->prev_cputime.stime);

    ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ptr)
        return 0;

    ptr->starttime_ns = timestamp;
    ptr->syscall_id = syscall_id;

    exec_parent = bpf_map_lookup_elem(&traced_tgids, &ptgid);

    if (exec_parent) {
        exec_span.span_base.parent.trace_id_hi = exec_parent->span_base.parent.trace_id_hi;
        exec_span.span_base.parent.trace_id_lo = exec_parent->span_base.parent.trace_id_lo;
        exec_span.span_base.parent.span_id = exec_parent->span_base.span_id;
        exec_span.span_base.span_id = timestamp;
    } else {
        exec_span.span_base.parent.trace_id_hi = tgid;
        exec_span.span_base.parent.trace_id_lo = timestamp;
        exec_span.span_base.span_id = timestamp;
    }

    exec_span.span_base.span_monotonic_timestamp_ns = timestamp;

    bpf_map_update_elem(&traced_tgids, &tgid, &exec_span, BPF_ANY);

    // bpf_printk("raw_tracepoint_sys_enter function call: %s; PID = : %d, Time: %d\n", comm, pid, timestamp);
    // bpf_printk("raw_tracepoint_sys_enter ptr: Sys: %d, Time: %d\n", ptr->syscall_id, ptr->starttime_ns);

    // u64 ts = bpf_ktime_get_ns();
    // struct request *rq = (struct request *) ctx->args[0];
    // bpf_map_update_elem(&start, &rq, &ts, 0);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    char comm[TASK_COMM_LEN];
    u64 timestamp = bpf_ktime_get_ns();
    struct task_struct *task;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    struct exec_span_t *exec_parent;
    struct exec_span_t exec_span = { 0 };

    // bpf_printk("sys_exit task_struct: TGID: %d, PARENT: %d\n", tgid, ptgid);

    bpf_get_current_comm(&comm, sizeof(comm));
    int foundKamailio = 0;

    if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
        comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0') {
        foundKamailio = 1;
    }

    if (foundKamailio == 0) {
        return 1;
    }

    task = bpf_get_current_task_btf();
    if (task->pid != pid)
        return 0;

    u64 tgid = task->tgid, ptgid = task->real_parent->tgid;

    // u64 current_uid_gid = bpf_get_current_uid_gid();
    // u32 uid = current_uid_gid;
    // bpf_printk("raw_tracepoint_sys_exit: %s; PID = : %u, Ts: %u\n", comm, pid, timestamp);

    struct data_t *ptr;
    ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ptr)
        return 0;

    u64 latency_ns = timestamp - ptr->starttime_ns;

    if (ptr->starttime_ns == 0) {
        latency_ns = 100;
    }

    // bpf_printk("raw_tracepoint_sys_exit Latency: %d, Exit code:%d, CPU:%d\n", latency_ns, task->exit_code,
    // task->recent_used_cpu);

    struct request *rq = (struct request *) ctx->args[0];
    struct gendisk *disk = BPF_CORE_READ(rq, q, disk);

    // u64 *issue_ts_ptr;
    // issue_ts_ptr = bpf_map_lookup_elem(&start, &rq);
    // if (!issue_ts_ptr) {
    //     return 0;
    //}

    // submit_kamailio_span(&kamailio_service_spans, struct disk_span_t, rq, {

    exec_parent = bpf_map_lookup_elem(&traced_tgids, &ptgid);

    if (exec_parent) {
        exec_span.span_base.parent.trace_id_hi = exec_parent->span_base.parent.trace_id_hi;
        exec_span.span_base.parent.trace_id_lo = exec_parent->span_base.parent.trace_id_lo;
        exec_span.span_base.parent.span_id = exec_parent->span_base.span_id;
        exec_span.span_base.span_id = timestamp;
    } else {
        exec_span.span_base.parent.trace_id_hi = tgid;
        exec_span.span_base.parent.trace_id_lo = timestamp;
        exec_span.span_base.span_id = timestamp;
    }

    exec_span.span_base.span_monotonic_timestamp_ns = timestamp;

    bpf_map_update_elem(&traced_tgids, &tgid, &exec_span, BPF_ANY);

    // memcmp_fallback(span.exe, BASH_PATH, sizeof(BASH_PATH));

    submit_kamailio_span_extra(&kamailio_service_spans, struct disk_span_t, exec_span.span_base.parent.trace_id_hi,
                               exec_span.span_base.parent.trace_id_lo, {
                                   span->span_base.parent.span_id = exec_span.span_base.parent.span_id;
                                   span->span_base.span_id = exec_span.span_base.span_id;
                                   span->span_base.span_duration_ns = latency_ns;
                                   span->span_base.span_monotonic_timestamp_ns = timestamp;
                                   span->dev =
                                       disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
                                   span->syscall_id = ptr->syscall_id;
                                   span->exit_code = task->exit_code;
                                   span->recent_used_cpu = task->recent_used_cpu;
                                   span->op = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
                                   span->span_name = ptr->syscall_id;
                               });

    // bpf_map_delete_elem(&enter_id, task);

    // bpf_map_delete_elem(&start, &rq);

    /*

    struct func_data_event_t *event = create_func_data_event(current_pid_tgid, timestamp);
    if (event == NULL)
    {
        return 0;
    }

    event->syscall_id = ptr->syscall_id;
    event->timestamp_ns = timestamp;
    event->latency_ns = timestamp - ptr->starttime_ns;
    event->nr_cpus_allowed = task->nr_cpus_allowed;
    event->recent_used_cpu = task->recent_used_cpu;
    event->exit_code = task->exit_code;

    bpf_printk("raw_tracepoint_sys_exit Latency: %d, Exit code:%d, CPU:%d\n", event->latency_ns, task->exit_code,
    task->recent_used_cpu);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct func_data_event_t));

    */

    return 0;
}

SEC("uprobe//usr/local/kamailio/sbin/kamailio:receive_msg")
int receive_msg(struct pt_regs *ctx)
{
    char comm[TASK_COMM_LEN];
    u64 timestamp = bpf_ktime_get_ns();
    struct data_t *ptr;
    struct task_struct *task;
    struct exec_span_t *exec_parent;
    struct exec_span_t exec_span = { 0 };

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    int foundKamailio = 0;

    if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
        comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0') {
        foundKamailio = 1;
    }

    if (foundKamailio == 0) {
        return 1;
    }

    task = bpf_get_current_task_btf();
    if (task->pid != pid)
        return 0;

    u64 tgid = task->tgid, ptgid = task->real_parent->tgid;
    bpf_printk("receive_msg receive_msg: TGID: %d, PARENT: %d\n", tgid, ptgid);

    // u64 current_pid_tgid = bpf_get_current_pid_tgid();
    // u32 pid = current_pid_tgid >> 32;
    // u64 current_uid_gid = bpf_get_current_uid_gid();
    // u32 uid = current_uid_gid;
    unsigned long syscall_id = 100;

    task = bpf_get_current_task_btf();
    if (task->pid != pid)
        return 0;

    bpf_printk("user_function task_struct: Time: %d, CPUTime: %d\n", task->start_time, task->prev_cputime.stime);

    ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ptr)
        return 0;

    ptr->starttime_ns = timestamp;
    ptr->syscall_id = syscall_id;

    bpf_printk("user_function function call: %s; PID = : %d, Time: %d\n", comm, pid, timestamp);
    bpf_printk("user_function ptr: Sys: %d, Time: %d\n", ptr->syscall_id, ptr->starttime_ns);

    exec_parent = bpf_map_lookup_elem(&traced_tgids, &ptgid);

    if (exec_parent) {
        exec_span.span_base.parent.trace_id_hi = exec_parent->span_base.parent.trace_id_hi;
        exec_span.span_base.parent.trace_id_lo = exec_parent->span_base.parent.trace_id_lo;
        exec_span.span_base.parent.span_id = exec_parent->span_base.span_id;
        exec_span.span_base.span_id = timestamp;
    } else {
        exec_span.span_base.parent.trace_id_hi = tgid;
        exec_span.span_base.parent.trace_id_lo = timestamp;
        exec_span.span_base.span_id = timestamp;
    }

    exec_span.span_base.span_monotonic_timestamp_ns = timestamp;

    bpf_map_update_elem(&traced_tgids, &tgid, &exec_span, BPF_ANY);

    return 0;
}

SEC("uretprobe//usr/local/kamailio/sbin/kamailio:receive_msg")
int user_ret_function(struct pt_regs *ctx)
{
    char comm[TASK_COMM_LEN];
    u64 timestamp = bpf_ktime_get_ns();
    struct task_struct *task;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    struct exec_span_t *exec_parent;
    struct exec_span_t exec_span = { 0 };

    // bpf_printk("sys_exit task_struct: TGID: %d, PARENT: %d\n", tgid, ptgid);

    bpf_get_current_comm(&comm, sizeof(comm));
    int foundKamailio = 0;

    if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
        comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0') {
        foundKamailio = 1;
    }

    if (foundKamailio == 0) {
        return 1;
    }

    task = bpf_get_current_task_btf();
    if (task->pid != pid)
        return 0;

    u64 tgid = task->tgid, ptgid = task->real_parent->tgid;

    struct data_t *ptr;
    ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ptr)
        return 0;

    u64 latency_ns = timestamp - ptr->starttime_ns;

    // bpf_printk("raw_tracepoint_sys_exit Latency: %d, Exit code:%d, CPU:%d\n", latency_ns, task->exit_code,
    // task->recent_used_cpu);

    exec_parent = bpf_map_lookup_elem(&traced_tgids, &ptgid);

    if (exec_parent) {
        exec_span.span_base.parent.trace_id_hi = exec_parent->span_base.parent.trace_id_hi;
        exec_span.span_base.parent.trace_id_lo = exec_parent->span_base.parent.trace_id_lo;
        exec_span.span_base.parent.span_id = exec_parent->span_base.span_id;
        exec_span.span_base.span_id = timestamp;
    } else {
        exec_span.span_base.parent.trace_id_hi = tgid;
        exec_span.span_base.parent.trace_id_lo = timestamp;
        exec_span.span_base.span_id = timestamp;
    }

    exec_span.span_base.span_monotonic_timestamp_ns = timestamp;

    bpf_map_update_elem(&traced_tgids, &tgid, &exec_span, BPF_ANY);

    submit_kamailio_span_extra(&kamailio_service_spans, struct disk_span_t, exec_span.span_base.parent.trace_id_hi,
                               exec_span.span_base.parent.trace_id_lo, {
                                   span->span_base.parent.span_id = exec_span.span_base.parent.span_id;
                                   span->span_base.span_id = exec_span.span_base.span_id;
                                   span->span_base.span_duration_ns = latency_ns;
                                   span->span_base.span_monotonic_timestamp_ns = timestamp;
                                   span->span_base.span_duration_ns = latency_ns;
                                   span->dev = 0;
                                   span->syscall_id = 3000;
                                   span->exit_code = task->exit_code;
                                   span->recent_used_cpu = task->recent_used_cpu;
                                   span->op = 0;
                                   span->span_name = 3000;
                               });

    // bpf_map_delete_elem(&enter_id, task);

    // bpf_map_delete_elem(&traced_tgids, &tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
