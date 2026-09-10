"""Native syscall/export wiring contracts; behavioral conversion tests live alongside these."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NetworkSyscallContracts(unittest.TestCase):
    def test_default_profiles_include_entry_and_exit(self):
        source = (ROOT / "src/trace.c").read_text()
        for profile in ("perfetto_compact_traces", "perfetto_detailed_traces"):
            block = source.split("static char " + profile + "[] =", 1)[1].split(";", 1)[0]
            self.assertIn("network_sys_enter", block)
            self.assertIn("network_sys_exit", block)

    def test_native_syscall_numbers_are_configured(self):
        source = (ROOT / "src/anettrace.c").read_text()
        for name in ("sendto", "recvfrom", "sendmsg", "recvmsg"):
            self.assertIn("SYS_" + name, source)

    def test_pairing_is_per_task_and_consumed_on_exit(self):
        source = (ROOT / "src/progs/core.c").read_text()
        self.assertIn("m_network_syscalls", source)
        self.assertIn("bpf_map_delete_elem(&m_network_syscalls, &pid_tgid)", source)
        self.assertIn("network_syscall_bind(info)", source)

    def test_syscall_export_does_not_add_traffic_bytes(self):
        source = (ROOT / "src/perfetto_export.c").read_text()
        block = source.split("static void export_network_syscall(", 1)[1].split(
            "static void handle_network_syscall(", 1)[0]
        self.assertNotIn("tx_bytes +=", block)
        self.assertNotIn("rx_bytes +=", block)
        self.assertIn('"Network syscalls"', block)
        self.assertIn('"incomplete"', block)

    def test_native_pairing_results_and_fd_reuse(self):
        """Compile real pairing/export functions; mock only native writer/track plumbing."""
        shared = (ROOT / "src/progs/shared.h").read_text()
        struct_end = shared.index("} network_syscall_event_t;") + len("} network_syscall_event_t;")
        struct_start = shared.rfind("typedef struct {", 0, struct_end)
        source = (ROOT / "src/perfetto_export.c").read_text()
        functions = source[source.index("static void export_network_syscall("):
                           source.index("void perfetto_export_event(")]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
typedef long long s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define PERFETTO_SCHEMA "anettrace.perfetto.v1"
#define NATIVE_TRACK_SYSCALL 1
''' + shared[struct_start:struct_end] + r'''
struct proto_buffer { int unused; };
struct native_track { u64 uuid; };
struct flow_state { u64 id, socket_id; };
static struct flow_state flow = {123, 99};
static struct native_track track = {1};
static struct { network_syscall_event_t event; u64 flow_id, completed_ts; bool active; }
    pending_syscalls[4096];
static size_t pending_syscall_count;
static u64 lost_events;
static u64 native_ring_window_ns, native_ring_latest_ns;
static FILE *export_file, *native_file;
static u64 begin_ts, end_ts;
static unsigned event_type, begins, ends;
static struct flow_state *flow_find_any(u64 id) { return id == 123 ? &flow : NULL; }
static u64 socket_instance_id(u64 key, u32 gen) { return key + gen; }
static u64 native_uuid(const char *s, u64 a, u64 b) { return a ^ b; }
static void format_flow_label(struct flow_state *f, char *s, size_t n) { snprintf(s,n,"tcp-1"); }
static struct native_track *native_find_track(u64 id) { return &track; }
static struct native_track *native_thread_track(u32 p,u32 t,const char *s) { return &track; }
static struct native_track *native_add_track(u64 a,u64 b,int k) { return &track; }
static void native_descriptor(u64 a,const char *s,u64 b,int k,u32 p,u32 t) {}
static void native_event_start(struct proto_buffer *e,u32 t,u64 id,const char *s,const char *c) { event_type=t; }
static void native_annotation_string(struct proto_buffer *e,const char *k,const char *v) {}
static void native_annotation_id(struct proto_buffer *e,const char *k,u64 v) {}
static void native_annotation_uint(struct proto_buffer *e,const char *k,u64 v) {}
static void native_annotation_int(struct proto_buffer *e,const char *k,s64 v) {}
static void native_annotation_bool(struct proto_buffer *e,const char *k,bool v) {}
static void native_event_write(u64 ts,struct proto_buffer *e) {
    if(event_type==1) { begins++; begin_ts=ts; } else { ends++; end_ts=ts; }
}
static void proto_free(struct proto_buffer *e) {}
''' + functions + r'''
int main(void) {
    export_file=stdout; native_file=stdout;
    network_syscall_event_t call={.kind=0,.start_ts=100,.ts=100,
        .tid=7,.tgid=6,.fd=9,.requested_bytes=10,.requested_valid=1};
    handle_network_syscall(&call);
    pending_syscalls[0].flow_id=123;
    call.finished=1; call.ts=120; call.socket_key=98; call.socket_generation=1; call.result=5;
    handle_network_syscall(&call);
    assert(begins==1 && ends==1 && begin_ts==100 && end_ts==120);
    assert(!pending_syscalls[0].active);
    call.finished=0; handle_network_syscall(&call); /* late START: ignored */
    assert(!pending_syscalls[0].active);
    call.start_ts=200; call.ts=200; call.socket_key=0; call.socket_generation=0;
    handle_network_syscall(&call);
    pending_syscalls[0].flow_id=123;
    call.finished=1; call.ts=230; call.socket_key=198; call.socket_generation=1; call.result=-11;
    handle_network_syscall(&call); /* reused fd, different socket: no old flow */
    call.start_ts=300; call.ts=350; call.result=0; call.requested_valid=0;
    export_network_syscall(&call,0,true); /* trace ended while blocked */
    call.require_socket=1; call.socket_key=0;
    export_network_syscall(&call,0,false); /* unmatched packet filter: omitted */
    assert(begins==3 && ends==3);
    call.require_socket=0; call.start_ts=1000; call.ts=2000;
    native_ring_window_ns=100; native_ring_latest_ns=0;
    export_network_syscall(&call,0,false);
    assert(begin_ts==1900 && end_ts==2000); /* first event after long blocking */
    native_ring_window_ns=0;
    call.start_ts=3000; call.ts=3000; call.finished=0;
    handle_network_syscall(&call);
    call.start_ts=4000; call.ts=4050; call.finished=1;
    handle_network_syscall(&call); /* newer call's CPU buffer polled first */
    call.start_ts=3000; call.ts=3050;
    handle_network_syscall(&call); /* older completed call must not be dropped */
    assert(!pending_syscalls[0].active && begins==6 && ends==6);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            cfile, binary = Path(tmp) / "syscall.c", Path(tmp) / "syscall"
            cfile.write_text(harness)
            result = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                     "-Wno-unused-parameter", str(cfile), "-o", str(binary)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        records = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(len(records), 6)
        self.assertEqual(records[0]["bytes"], 5)  # partial write, not requested size
        self.assertEqual(records[0]["flow_tag"], "tcp-1")
        self.assertEqual(records[0]["duration_ns"], 20)
        self.assertEqual(records[1]["error"], 11)
        self.assertEqual(records[1]["bytes"], 0)
        self.assertEqual(records[1]["flow_id"], "0000000000000000")
        self.assertTrue(records[2]["incomplete"])


if __name__ == "__main__":
    unittest.main()
