"""Compile the bounded pending-RX gate and check only exact evidence can release data."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RxContextTests(unittest.TestCase):
    def test_exact_instance_gate_bounds_and_out_of_order_evidence(self):
        source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef long long s64;
typedef int32_t s32;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint64_t __u64;
#define RX_CONTEXT_MAX_EVENTS 3
#define RX_CONTEXT_MAX_BYTES 4096
#define RX_CONTEXT_OWNER_SLOTS 8
#define RX_CONTEXT_WINDOW_NS 100
#include "src/progs/shared.h"
#include "src/rx_context.h"
static unsigned emitted;
static detail_event_t last;
static void emit(const void *data, int cpu, u32 size) {
    assert(cpu==7 && size==sizeof(detail_event_t));
    last=*(const detail_event_t *)data; emitted++;
    assert(!last.owner_pending);
}
static detail_event_t packet(u64 key, u32 generation, u64 ts, bool proof) {
    detail_event_t d={.key=key,.key_generation=generation,.tid=44,.tgid=45,
        .direction=PACKET_DIRECTION_RX,.owner_pending=!proof,.owner_evidence=proof,
        .owner_valid=proof,.owner_tid=proof ? 99 : 0,.owner_tgid=proof ? 98 : 0,
        .owner_uid=proof ? 1000 : 0,.owner_socket_key=proof ? 123 : 0,
        .owner_socket_generation=proof ? 2 : 0};
    d.pkt.ts=ts; return d;
}
static void feed(struct rx_context *s, detail_event_t d) {
    rx_context_feed(s,&d,7,sizeof(d),emit);
}
int main(void) {
    struct rx_context s={0};
    feed(&s,packet(1,1,100,false)); assert(!emitted && s.count==1);
    feed(&s,packet(1,2,110,true)); assert(emitted==1 && s.count==1);
    feed(&s,packet(1,1,120,true)); assert(emitted==3 && !s.count && s.replayed==1);
    /* A late early event can use later exact evidence already delivered. */
    feed(&s,packet(1,1,105,false)); assert(emitted==4 && last.pkt.ts==105);
    assert(last.tid==44 && last.tgid==45 && last.owner_tid==99);
    assert(last.owner_evidence==2 && last.owner_socket_key==123);
    /* A future event cannot borrow an older observation. */
    feed(&s,packet(1,1,130,false)); assert(emitted==4 && s.count==1);
    rx_context_expire(&s,231); assert(!s.count && s.expired==1);
    feed(&s,packet(1,1,110,false)); assert(emitted==4 && s.expired==2);
    /* Generation zero cannot support safe pointer reuse association. */
    feed(&s,packet(3,0,240,false)); assert(!s.count && s.unresolved==1);
    for (u64 i=0;i<4;i++) feed(&s,packet(10+i,1,250+i,false));
    assert(s.count==3 && s.capacity_dropped==1 && s.bytes<=RX_CONTEXT_MAX_BYTES);
    rx_context_finish(&s); assert(!s.count && !s.bytes && s.unresolved==4);
    /* Even with a matching instance, TX evidence cannot release RX. */
    feed(&s,packet(50,1,400,false));
    detail_event_t tx=packet(50,1,410,true); tx.direction=PACKET_DIRECTION_TX;
    feed(&s,tx); assert(s.count==1);
    rx_context_finish(&s);
    /* A metadata allocation that exceeds the byte limit is never retained. */
    unsigned char large[RX_CONTEXT_MAX_BYTES]={0};
    detail_event_t *d=(void *)large; *d=packet(70,1,500,false);
    rx_context_feed(&s,d,7,sizeof(large),emit);
    assert(!s.count && s.capacity_dropped==2);
    printf("ok\n");
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            cfile, binary = Path(tmp) / "rx.c", Path(tmp) / "rx"
            cfile.write_text(source)
            result = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                     "-I", str(ROOT), str(cfile), "-o", str(binary)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ok\n")


    def test_export_entry_quarantines_unknown_and_rechecks_target(self):
        from tests.test_flow_identity import FlowIdentityTests, function
        source = (ROOT / "src/perfetto_export.c").read_text()
        helper = r'''
#include <assert.h>
#include <pthread.h>
typedef long long s64;
typedef int32_t s32;
#include "src/progs/shared.h"
#include "src/rx_context.h"
typedef struct { bool socket; } trace_t;
static trace_t trace;
static FILE *export_file, *native_file;
static struct { bpf_args_t bpf_args; } trace_ctx;
static struct rx_context rx_context;
static pthread_mutex_t rx_context_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned emitted;
static detail_event_t received[4];
static trace_t *get_trace(u16 index) { (void)index; return &trace; }
static bool trace_using_sk(trace_t *t) { return t->socket; }
static void perfetto_export_event_now(const void *data,int cpu,u32 size) {
    (void)cpu; assert(size==sizeof(detail_event_t)); received[emitted++]=*(const detail_event_t *)data;
}
''' + function(source, "perfetto_export_event")
        result = FlowIdentityTests.run_source(self, helper, r'''
export_file=stdout;
trace_ctx.bpf_args.rx_context=true; trace_ctx.bpf_args.uid_enabled=true; trace_ctx.bpf_args.uid=1000;
detail_event_t d={.meta=FUNC_TYPE_FUNC,.key=1,.key_generation=2,
    .owner_pending=1,.direction=PACKET_DIRECTION_RX,.tid=88}; d.pkt.ts=100;
perfetto_export_event(&d,4,sizeof(d)); assert(!emitted);
d.owner_pending=0; d.owner_evidence=1; d.owner_valid=1;
d.owner_socket_key=99; d.owner_socket_generation=1; d.owner_uid=2000; d.pkt.ts=110;
perfetto_export_event(&d,4,sizeof(d)); assert(!emitted);
d.owner_uid=1000;
perfetto_export_event(&d,4,sizeof(d)); assert(emitted==2);
assert(received[0].pkt.ts==100 && received[0].tid==88 && received[0].owner_evidence==2);
assert(received[1].pkt.ts==110 && received[1].owner_evidence==1);
/* A cached socket creator does not establish the actual receiving TID. */
trace_ctx.bpf_args.pid=99; d.owner_tid=99;
perfetto_export_event(&d,4,sizeof(d)); assert(emitted==2);
printf("ok");
rx_context_finish(&rx_context);
''')
        self.assertEqual(result, ["ok"])

    def test_pending_entry_and_fexit_never_reach_terminal(self):
        from tests.test_flow_identity import FlowIdentityTests, function
        helper = r'''
typedef long long s64; typedef int32_t s32;
#include "src/progs/shared.h"
static unsigned terminal;
static bool trace_stopped(void) { return false; }
static void perfetto_export_event(const void *d,int c,u32 s) {(void)d;(void)c;(void)s;}
static bool capture_async;
#define capture_queue_event perfetto_export_event
static void terminal_poll(void *x,int c,void *d,u32 s) {(void)x;(void)c;(void)d;(void)s;terminal++;}
static struct { struct {void (*trace_poll)(void *,int,void *,u32);} *ops;} trace_ctx;
''' + function((ROOT / "src/trace.c").read_text(), "poll_handler_wrap")
        result = FlowIdentityTests.run_source(self, helper, r'''
typeof(*trace_ctx.ops) ops={.trace_poll=terminal_poll}; trace_ctx.ops=&ops;
detail_event_t d={.meta=FUNC_TYPE_FUNC,.owner_pending=1};
poll_handler_wrap(NULL,0,&d,sizeof(d));
d.meta=FUNC_TYPE_TRACING_RET;
poll_handler_wrap(NULL,0,&d,sizeof(d));
printf("%u ",terminal);
d.owner_pending=0;
poll_handler_wrap(NULL,0,&d,sizeof(d));
printf("%u",terminal);
''')
        self.assertEqual(result, ["0", "1"])


if __name__ == "__main__":
    unittest.main()
