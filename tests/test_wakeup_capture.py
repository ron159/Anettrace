"""Exercise the real scheduler capture helpers with in-memory BPF maps."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WakeupCaptureTests(unittest.TestCase):
    def test_scheduler_evidence_lifetime_and_context(self):
        helper = ROOT / "src/progs/network_wakeup.h"
        self.assertTrue(helper.exists(), "scheduler capture helper is missing")
        shared = (ROOT / "src/progs/shared.h").read_text()
        end = shared.index("} network_syscall_event_t;") + len("} network_syscall_event_t;")
        start = shared.rfind("typedef struct {", 0, end)
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
#define SEC(s)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define __uint(n,v) int n
#define __type(n,t) t *n
#define TRACE_NAME(n) n
#define _(v) (v)
#define _C(v,f) ((v)->f)
#define _LC(dst,v,f) bpf_probe_read_kernel(dst,sizeof(*(dst)),&((v)->f))
#define __kconfig
#define __ksym
#undef __weak
#define __weak __attribute__((weak))
#define preserve_access_index unused
#define __TARGET_ARCH_arm64
#define bpf_core_field_exists(f) (strstr(#f,"softirq_disable_cnt") ? rt_enabled : field_available)
#define bpf_core_enum_value_exists(t,f) helper_available
#define bpf_ksym_exists(s) ((const void *)(s)==(const void *)&__preempt_count ? symbol_available : hot_available)
#define BPF_MAP_TYPE_LRU_HASH 1
#define BPF_ANY 0
typedef struct { bool ready, perfetto, wakeup_chain, uid_enabled; u32 pid, uid; } bpf_args_t;
static bpf_args_t config = {.ready=true, .perfetto=true, .wakeup_chain=true,
    .uid_enabled=true, .uid=1000};
#define CONFIG() (&config)
int LINUX_KERNEL_VERSION = (6<<16)|(8<<8);
static bool field_available=true, rt_enabled=false, read_fail=false;
#ifdef __TARGET_ARCH_x86
static bool helper_available=true, symbol_available=true, hot_available=true;
static u32 cpu_preempt_count;
static void *bpf_this_cpu_ptr(const void *);
#endif
struct task_struct {
    int softirq_disable_cnt;
    u64 start_time;
    struct { struct { u32 count; } preempt; } thread_info;
};
static struct task_struct current;
static u64 task_id, now;
static u32 uid=1000, cpu;
static u64 bpf_get_current_pid_tgid(void) { return task_id; }
static u64 bpf_get_current_uid_gid(void) { return uid; }
static u32 bpf_get_smp_processor_id(void) { return cpu; }
static u64 bpf_ktime_get_ns(void) { return now; }
static void *bpf_get_current_task(void) { return &current; }
static int bpf_probe_read_kernel(void *dst, unsigned n, const void *src) {
    if(read_fail) return -1;
    memcpy(dst,src,n); return 0;
}
static int bpf_get_current_comm(char *s, unsigned n) { memset(s, 0, n); memcpy(s,"waker",5); return 0; }
static bool perfetto_current_matches(bpf_args_t *a,u32 tid,u32 id) {
    return (!a->pid || a->pid==tid) && (!a->uid_enabled || a->uid==id);
}
static void *bpf_map_lookup_elem(void *,const void *);
static int bpf_map_update_elem(void *,const void *,const void *,int);
''' + shared[start:end] + '\n#include "' + str(helper) + r'''"
#ifdef __TARGET_ARCH_x86
const int __preempt_count = 0;
struct pcpu_hot___wakeup pcpu_hot;
static void *bpf_this_cpu_ptr(const void *ptr) {
    return ptr==&__preempt_count ? (void *)&cpu_preempt_count : (void *)&pcpu_hot;
}
#endif
static void set_preempt_count(u32 count) {
    current.thread_info.preempt.count=count;
#ifdef __TARGET_ARCH_x86
    cpu_preempt_count=count; pcpu_hot.preempt_count=count;
#endif
}
static network_wakeup_state_t states[256];
static bool present[256];
static void *bpf_map_lookup_elem(void *map,const void *key) {
    u32 tid=*(const u32 *)key;
    assert(map==&m_network_wakeups);
    return tid<256 && present[tid] ? &states[tid] : 0;
}
static int bpf_map_update_elem(void *map,const void *key,const void *value,int flags) {
    u32 tid=*(const u32 *)key;
    assert(map==&m_network_wakeups && tid<256);
    states[tid]=*(const network_wakeup_state_t *)value;
    present[tid]=true;
    return 0;
}
static void set_task(u32 tid, u32 tgid, u64 birth) {
    task_id=((u64)tgid<<32)|tid; current.start_time=birth;
}
static network_syscall_event_t snapshot(void) {
    network_syscall_event_t e={.start_ts=now};
    network_wakeup_snapshot(&e);
    return e;
}
static void switch_task(u32 prev,u32 next) {
    network_sched_switch_ctx_t ctx={.prev_pid=prev,.next_pid=next};
    network_sched_switch(&ctx);
}
static void wake(u32 target,u32 count) {
    /* The real BPF header is a pt_regs pointer, not trace_entry flags. */
    network_sched_wakeup_ctx_t ctx={.pid=target,.reserved=0xffff000000c20000ULL};
    set_preempt_count(count);
    network_sched_waking(&ctx); now++;
    network_sched_wakeup(&ctx);
}
int main(void) {
    network_syscall_event_t e;
    /* Disabled is distinguishable from unavailable scheduler evidence. */
    set_task(7,7,100); now=1000; config.wakeup_chain=false;
    e=snapshot(); assert(e.wakeup_status==0 && !present[7]);
    config.wakeup_chain=true;
    e=snapshot(); assert(e.wakeup_status==1 && present[7]);
    /* Real successful wake and first running boundary. */
    switch_task(7,8); set_task(8,8,200); now=1100; cpu=2;
    network_sched_wakeup_ctx_t first={.pid=7}; network_sched_waking(&first);
    /* Successful activation can run on a remote CPU in an unrelated task. */
    now=1101; cpu=3; set_task(9,9,300); network_sched_wakeup(&first);
    now=1200; switch_task(9,7);
    set_task(7,7,100); now=1250; e=snapshot();
    assert(e.wakeup_status==2 && e.waking_ts==1100 && e.wakeup_ts==1101);
    assert(e.run_start_ts==1200 && e.waking_cpu==2 && e.run_cpu==3);
    assert(e.waker_tid==8 && e.waker_tgid==8 && e.waker_start_time==200);
    assert(e.waking_context==1 && !strcmp(e.waker_task,"waker"));
    /* Exercise real count reads independently of scheduler sequencing. */
    u32 raw;
    set_preempt_count(0x80000202U); raw=0;
    assert(network_wakeup_context(&raw)==1 && raw==0x80000202U);
    /* BH-disabled alone is task; serving-softirq is the low softirq bit. */
    set_preempt_count(0x300); assert(network_wakeup_context(&raw)==3);
    rt_enabled=true; current.softirq_disable_cnt=0;
    assert(network_wakeup_context(&raw)==1);
    current.softirq_disable_cnt=0x100; set_preempt_count(2);
    assert(network_wakeup_context(&raw)==3);
    rt_enabled=false;
    read_fail=true; assert(network_wakeup_context(&raw)==0); read_fail=false;
    LINUX_KERNEL_VERSION=7<<16; assert(network_wakeup_context(&raw)==0);
    LINUX_KERNEL_VERSION=(6<<16)|(8<<8);
    set_preempt_count(1<<24); assert(network_wakeup_context(&raw)==0);
#ifdef __TARGET_ARCH_x86
    symbol_available=false; set_preempt_count(2);
    assert(network_wakeup_context(&raw)==1 && raw==2);
    hot_available=false; assert(network_wakeup_context(&raw)==0);
    hot_available=true; field_available=false; assert(network_wakeup_context(&raw)==0);
    field_available=true; symbol_available=true; helper_available=false;
    assert(network_wakeup_context(&raw)==0); helper_available=true;
#else
    field_available=false; assert(network_wakeup_context(&raw)==0);
    field_available=true;
#endif
    set_preempt_count(0);
    /* Another syscall in the same running segment may retain this evidence. */
    now=1260; e=snapshot(); assert(e.wakeup_status==2);
    /* Preemption and resumption without a new wake cannot inherit the old edge. */
    switch_task(7,8); set_task(8,8,200); now=1300; switch_task(8,7);
    set_task(7,7,100); now=1350; e=snapshot();
    assert(e.wakeup_status==3 && e.run_start_ts==1300 && !e.waking_ts && !e.waker_tid);
    /* Waking without successful wakeup does not become a confirmed edge. */
    switch_task(7,8); set_task(8,8,200); now=1400;
    network_sched_wakeup_ctx_t ctx={.pid=7}; network_sched_waking(&ctx);
    now=1450; switch_task(8,7); set_task(7,7,100); now=1460; e=snapshot();
    assert(e.wakeup_status==3 && !e.waking_ts && !e.waker_tid);
    /* IRQ/softirq/NMI current task is not the waker. */
    const u32 counts[]={0x10000,0x100,0x110000};
    for(unsigned i=0;i<3;i++) {
        switch_task(7,8); set_task(8,8,200); now+=10; wake(7,counts[i]);
        now+=10; switch_task(8,7); set_task(7,7,100); now++; e=snapshot();
        assert(e.wakeup_status==2 && e.waking_context==i+2);
        assert(e.waking_preempt_count==counts[i] && !e.waker_tid && !e.waker_tgid);
        assert(!e.waker_start_time && !e.waker_task[0]);
    }
    /* Unavailable context retains real wake timestamps but no task identity. */
    switch_task(7,8); set_task(8,8,200); now+=10;
    read_fail=true; wake(7,0); read_fail=false;
    now+=10; switch_task(8,7); set_task(7,7,100); now++; e=snapshot();
    assert(e.wakeup_status==2 && !e.waking_context && !e.waker_tid);
    assert(!e.waking_preempt_count && !e.waker_start_time && !e.waker_task[0]);
    /* Garbage common-header bits cannot turn a task wake into NMI. */
    switch_task(7,8); set_task(8,8,200); now+=10; wake(7,2);
    now+=10; switch_task(8,7); set_task(7,7,100); now++; e=snapshot();
    assert(e.wakeup_status==2 && e.waking_context==1 && e.waker_tid==8);
    /* Recycled TID with a new birth time cannot inherit any old wake/run data. */
    set_task(7,7,999); now++; e=snapshot();
    assert(e.wakeup_status==1 && !e.waking_ts && !e.run_start_ts);
    /* Unknown tasks and out-of-scope identities are never promoted by wake. */
    wake(99,0); assert(!present[99]);
    set_task(99,99,999); uid=1001; e=snapshot(); assert(!present[99]);
    switch_task(99,7); assert(!present[99]);
    uid=1000; config.pid=7; e=snapshot(); assert(!present[99]);
    /* Missing start-time identity fails closed. */
    set_task(7,7,0); e=snapshot(); assert(e.wakeup_status==1 && !e.waking_ts);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp) / "wakeup.c", Path(tmp) / "wakeup"
            for arch in ("arm64", "x86"):
                with self.subTest(arch=arch):
                    source.write_text(harness.replace("#define __TARGET_ARCH_arm64",
                                                      f"#define __TARGET_ARCH_{arch}"))
                    build = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                            "-Wno-unused-parameter", str(source), "-o", str(binary)],
                                           text=True, capture_output=True)
                    self.assertEqual(build.returncode, 0, build.stderr)
                    result = subprocess.run([str(binary)], text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
