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
#define BPF_MAP_TYPE_LRU_HASH 1
#define BPF_ANY 0
typedef struct { bool ready, perfetto, wakeup_chain, uid_enabled; u32 pid, uid; } bpf_args_t;
static bpf_args_t config = {.ready=true, .perfetto=true, .wakeup_chain=true,
    .uid_enabled=true, .uid=1000};
#define CONFIG() (&config)
struct task_struct { u64 start_time; };
static struct task_struct current;
static u64 task_id, now;
static u32 uid=1000, cpu;
static u64 bpf_get_current_pid_tgid(void) { return task_id; }
static u64 bpf_get_current_uid_gid(void) { return uid; }
static u32 bpf_get_smp_processor_id(void) { return cpu; }
static u64 bpf_ktime_get_ns(void) { return now; }
static void *bpf_get_current_task(void) { return &current; }
static int bpf_get_current_comm(char *s, unsigned n) { memset(s, 0, n); memcpy(s,"waker",5); return 0; }
static bool perfetto_current_matches(bpf_args_t *a,u32 tid,u32 id) {
    return (!a->pid || a->pid==tid) && (!a->uid_enabled || a->uid==id);
}
static void *bpf_map_lookup_elem(void *,const void *);
static int bpf_map_update_elem(void *,const void *,const void *,int);
''' + shared[start:end] + '\n#include "' + str(helper) + r'''"
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
static void wake(u32 target,u8 flags) {
    network_sched_wakeup_ctx_t ctx={.pid=target,.flags=flags};
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
    const u8 flags[]={8,16,64};
    for(unsigned i=0;i<3;i++) {
        switch_task(7,8); set_task(8,8,200); now+=10; wake(7,flags[i]);
        now+=10; switch_task(8,7); set_task(7,7,100); now++; e=snapshot();
        assert(e.wakeup_status==2 && e.waking_context==i+2);
        assert(e.waking_flags==flags[i] && !e.waker_tid && !e.waker_tgid);
        assert(!e.waker_start_time && !e.waker_task[0]);
    }
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
            source.write_text(harness)
            build = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                    "-Wno-unused-parameter", str(source), "-o", str(binary)],
                                   text=True, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
