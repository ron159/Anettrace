"""Run the production traffic accounting helpers against small in-memory maps."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from tests import test_flow_identity as helpers

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/progs/traffic.c"


def function(source, name):
    match = re.search(r"^static [^\n]*\b" + name + r"\([^;]*?\n\{", source, re.M)
    if not match:
        raise AssertionError("Missing source function: " + name)
    brace = source.index("{", match.start())
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
#include "src/progs/traffic_shared.h"
#ifndef __always_inline
#define __always_inline inline
#endif
#define BPF_NOEXIST 1
#define MAP_CAPACITY 16
static int traffic_flows, traffic_stats, traffic_totals, traffic_processes;
static int traffic_inflight;
static traffic_flow_value_t global_value;
static bool fail_flow, fail_process, race_flow, race_process;
static u64 now_ns = 100, current_pid_tgid = ((u64)10 << 32) | 11;
static u64 stats[TRAFFIC_STAT_MAX];
struct task_struct {
    struct task_struct *group_leader;
    u64 start_time;
    char comm[16];
};
static struct task_struct leader = {.start_time=1000, .comm="process"};
static struct task_struct task = {.group_leader=&leader, .start_time=2000,.comm="worker"};
struct sock_common {
    u16 skc_family, skc_num, skc_dport;
    u32 skc_rcv_saddr, skc_daddr;
    struct in6_addr skc_v6_rcv_saddr, skc_v6_daddr;
};
struct sock { struct sock_common common; };
struct inet_sock { struct sock_common common; u16 inet_sport; };
static traffic_config_t traffic_config;
static bool fields_exist=true, fail_leader, fail_start, fail_comm;
static u64 bpf_ktime_get_ns(void) { return now_ns; }
static u64 bpf_get_current_pid_tgid(void) { return current_pid_tgid; }
static void *bpf_get_current_task(void) { return &task; }
static u64 bpf_get_current_uid_gid(void) { return 1000; }
static void bpf_get_current_comm(void *dst,size_t size) { memcpy(dst,task.comm,size); }
#define bpf_ntohs(value) ntohs(value)
#define BPF_CORE_READ(src,field) ((src)->field)
#define bpf_core_field_exists(field) fields_exist
static int core_read(void *dst, const void *src, size_t size, const char *field)
{
    if ((fail_leader && !strcmp(field,"group_leader")) ||
        (fail_start && !strcmp(field,"start_time")) ||
        (fail_comm && !strcmp(field,"comm"))) {
        memset(dst,0,size);
        return -EFAULT;
    }
    memcpy(dst,src,size);
    return 0;
}
#define BPF_CORE_READ_INTO(dst, src, field) \
    core_read((dst), &(src)->field, sizeof(*(dst)), #field)
static struct {
    bool used;
    traffic_flow_key_t key;
    traffic_flow_value_t value;
} flows[MAP_CAPACITY];
static struct {
    bool used;
    traffic_process_key_t key;
    traffic_process_value_t value;
} processes[MAP_CAPACITY];
struct traffic_inflight_value { traffic_flow_key_t flow; void *sk; };
static struct traffic_inflight_value inflight_value;
static bool inflight_exists;
struct pt_regs { u64 result; };
#define PT_REGS_RC(ctx) ((ctx)->result)
static void *bpf_map_lookup_elem(void *map, const void *key)
{
    if (map == &traffic_totals) return &global_value;
    if (map == &traffic_stats) return &stats[*(const u32 *)key];
    if (map == &traffic_inflight) return inflight_exists ? &inflight_value : NULL;
    for (int i=0;i<MAP_CAPACITY;i++) {
        if (map == &traffic_flows && flows[i].used &&
            !memcmp(key,&flows[i].key,sizeof(flows[i].key))) return &flows[i].value;
        if (map == &traffic_processes && processes[i].used &&
            !memcmp(key,&processes[i].key,sizeof(processes[i].key))) return &processes[i].value;
    }
    return NULL;
}
static int bpf_map_update_elem(void *map, const void *key, const void *value, int flags)
{
    (void)flags;
    if (bpf_map_lookup_elem(map,key)) return -EEXIST;
    if ((map == &traffic_flows && fail_flow) ||
        (map == &traffic_processes && fail_process)) return -ENOSPC;
    for (int i=0;i<MAP_CAPACITY;i++) {
        if (map == &traffic_flows && !flows[i].used) {
            flows[i].used=true;
            flows[i].key=*(const traffic_flow_key_t *)key;
            flows[i].value=*(const traffic_flow_value_t *)value;
            if (race_flow) {
                race_flow=false;
                flows[i].value.rx_bytes=7;
                return -EEXIST;
            }
            return 0;
        }
        if (map == &traffic_processes && !processes[i].used) {
            processes[i].used=true;
            processes[i].key=*(const traffic_process_key_t *)key;
            processes[i].value=*(const traffic_process_value_t *)value;
            if (race_process) {
                race_process=false;
                processes[i].value.counters.rx_bytes=7;
                return -EEXIST;
            }
            return 0;
        }
    }
    return -ENOSPC;
}
static int bpf_map_delete_elem(void *map, const void *key)
{
    if (map == &traffic_inflight) { inflight_exists=false; return 0; }
    for (int i=0;i<MAP_CAPACITY;i++)
        if (map == &traffic_flows && flows[i].used &&
            !memcmp(key,&flows[i].key,sizeof(flows[i].key))) {
            flows[i].used=false;
            return 0;
        }
    return -ENOENT;
}
'''


class TrafficAccountingTests(unittest.TestCase):
    def run_source(self, body):
        source = SOURCE.read_text()
        helpers = "".join(function(source, name) for name in (
            "traffic_stat_inc", "traffic_process_start", "traffic_fill_key", "traffic_counter_add",
            "traffic_account_process", "traffic_account", "traffic_exit"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            cfile, binary = path / "traffic.c", path / "traffic"
            cfile.write_text(PRELUDE + helpers + "int main(void) {\n" + body + "\n}\n")
            compiled = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-function", "-Wno-unused-variable", "-I", str(ROOT),
                 str(cfile), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.split()

    def test_protocol_selection_and_optional_endpoints(self):
        traffic = (ROOT / 'src/traffic.c').read_text()
        source = r'''
#include <errno.h>
#include <netinet/in.h>
#define TRAFFIC_MAX_LINKS 15
struct bpf_program { const char *name; bool autoload; };
struct bpf_link { int status; };
static struct bpf_program programs[] = {
    {"traffic_tcp_send_entry", true}, {"traffic_udp6_recv_exit", true},
    {"traffic_udp_receive_endpoints", true},
};
struct traffic { struct bpf_program *obj; };
#define bpf_object__for_each_program(prog, obj) \
    for (prog = obj; prog < obj + sizeof(programs)/sizeof(*programs); prog++)
#define bpf_program__name(prog) ((prog)->name)
static int bpf_program__set_autoload(struct bpf_program *program, bool autoload) {
    program->autoload = autoload; return 0;
}
static struct bpf_link unavailable = {-ENOENT}, attached;
static struct bpf_link *bpf_program__attach_kprobe(struct bpf_program *program,
        bool ret, const char *target) {
    return strcmp(target, "udp_send_skb") ? &attached : &unavailable;
}
#define libbpf_get_error(link) ((link)->status)
static unsigned warnings;
#define pr_warn(...) ((void)warnings++)
''' + function(traffic, 'traffic_select_programs') + function(traffic, 'traffic_attach_endpoint')
        result = helpers.FlowIdentityTests.run_source(self, source, r'''
struct traffic skel = { programs };
struct bpf_link *links[TRAFFIC_MAX_LINKS] = {};
int count = 0;
unsigned protocols[] = {0, IPPROTO_TCP, IPPROTO_UDP};
for (unsigned i = 0; i < 3; i++) {
    for (unsigned j = 0; j < 3; j++) programs[j].autoload = true;
    printf("%d ", traffic_select_programs(&skel, protocols[i]));
    printf("%d%d%d ", programs[0].autoload, programs[1].autoload, programs[2].autoload);
}
traffic_attach_endpoint(programs, "udp_send_skb", links, &count);
traffic_attach_endpoint(programs, "skb_consume_udp", links, &count);
printf("%d %u %d", count, warnings, links[0] == &attached);
''')
        self.assertEqual(result, ['0', '111', '0', '100', '0', '011', '1', '1', '1'])

    def test_flow_capacity_failure_retains_global_bytes(self):
        result = self.run_source(r'''
traffic_flow_key_t flow = {.tgid = 10, .tid = 11, .process_start_ns=1000};
fail_flow = true;
traffic_account(&flow, 128, false);
printf("%llu %llu %llu", (unsigned long long)global_value.rx_bytes,
       (unsigned long long)processes[0].value.counters.rx_bytes,
       (unsigned long long)stats[TRAFFIC_STAT_FLOW_DROP]);
''')
        self.assertEqual(result, ["128", "128", "1"])

    def test_process_capacity_failure_retains_global_and_flow_bytes(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11,.process_start_ns=1000};
fail_process=true;
traffic_account(&flow,256,true);
printf("%llu %llu %llu",(unsigned long long)global_value.tx_bytes,
       (unsigned long long)flows[0].value.tx_bytes,
       (unsigned long long)stats[TRAFFIC_STAT_PROCESS_DROP]);
''')
        self.assertEqual(result, ["256", "256", "1"])

    def test_missing_identity_preserves_bytes_without_merging_processes(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11};
traffic_account(&flow,128,false);
printf("%llu %llu %d %llu",(unsigned long long)global_value.rx_bytes,
       (unsigned long long)flows[0].value.rx_bytes,processes[0].used,
       (unsigned long long)stats[TRAFFIC_STAT_PROCESS_ID_MISS]);
''')
        self.assertEqual(result, ["128", "128", "0", "1"])

    def test_process_identity_uses_leader_and_checks_core_read_failures(self):
        result = self.run_source(r'''
printf("%llu ",(unsigned long long)traffic_process_start());
task.start_time=9999;
printf("%llu ",(unsigned long long)traffic_process_start());
fail_leader=true;
printf("%llu ",(unsigned long long)traffic_process_start());
fail_leader=false;fail_start=true;
printf("%llu ",(unsigned long long)traffic_process_start());
fail_start=false;fields_exist=false;
printf("%llu ",(unsigned long long)traffic_process_start());
fields_exist=true;task.group_leader=NULL;
printf("%llu",(unsigned long long)traffic_process_start());
''')
        self.assertEqual(result, ["1000", "1000", "0", "0", "0", "0"])

    def test_threads_aggregate_but_reused_tgid_stays_separate(self):
        result = self.run_source(r'''
traffic_flow_key_t first={.tgid=10,.tid=11,.process_start_ns=1000};
traffic_flow_key_t other=first;
other.tid=12;
traffic_account(&first,128,false);
traffic_account(&other,256,false);
first.process_start_ns=3000;
traffic_account(&first,512,false);
printf("%llu %llu %llu %llu %llu %s",
       (unsigned long long)global_value.rx_bytes,
       (unsigned long long)processes[0].value.counters.rx_bytes,
       (unsigned long long)processes[1].value.counters.rx_bytes,
       (unsigned long long)processes[0].key.start_time_ns,
       (unsigned long long)processes[1].key.start_time_ns,processes[0].value.comm);
''')
        self.assertEqual(result, ["896", "384", "512", "1000", "3000", "process"])

    def test_flow_recreation_preserves_totals_and_changes_only_flow_generation(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11,.process_start_ns=1000};
traffic_account(&flow,128,false);
now_ns=200;
traffic_account(&flow,256,false);
printf("%llu %llu ",(unsigned long long)flows[0].value.first_seen_ns,
       (unsigned long long)flows[0].value.last_seen_ns);
bpf_map_delete_elem(&traffic_flows,&flow);
now_ns=400;
traffic_account(&flow,512,false);
printf("%llu %llu %llu %llu %llu",
       (unsigned long long)flows[0].value.first_seen_ns,
       (unsigned long long)flows[0].value.rx_bytes,
       (unsigned long long)processes[0].value.counters.first_seen_ns,
       (unsigned long long)processes[0].value.counters.rx_bytes,
       (unsigned long long)global_value.rx_bytes);
''')
        self.assertEqual(result, ["100", "200", "400", "512", "100", "896", "896"])

    def test_noexist_insert_race_reuses_winning_values(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11,.process_start_ns=1000};
race_flow=race_process=true;
traffic_account(&flow,128,false);
printf("%llu %llu %llu %llu %llu",
       (unsigned long long)global_value.rx_bytes,
       (unsigned long long)flows[0].value.rx_bytes,
       (unsigned long long)processes[0].value.counters.rx_bytes,
       (unsigned long long)stats[TRAFFIC_STAT_PROCESS_DROP],
       (unsigned long long)stats[TRAFFIC_STAT_FLOW_DROP]);
''')
        self.assertEqual(result, ["128", "135", "135", "0", "0"])

    def test_counter_remains_64_bit_above_four_gib(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11,.process_start_ns=1000};
for (int i=0;i<5;i++) traffic_account(&flow,1ULL<<30,false);
traffic_account(&flow,33,true);
printf("%llu %llu %llu %llu",
       (unsigned long long)global_value.rx_bytes,
       (unsigned long long)processes[0].value.counters.rx_bytes,
       (unsigned long long)flows[0].value.rx_bytes,
       (unsigned long long)global_value.tx_bytes);
''')
        self.assertEqual(result, [str(5 << 30)] * 3 + ["33"])

    def test_signed_return_and_inflight_consumption_prevent_false_gigabytes(self):
        result = self.run_source(r'''
const u64 results[]={0xfffffff5ULL,0xfffffffcULL,0xffffff98ULL,0,1024};
struct pt_regs registers;
for (unsigned i=0;i<sizeof(results)/sizeof(results[0]);i++) {
    inflight_value.flow=(traffic_flow_key_t){.tgid=10,.tid=11,.process_start_ns=1000};
    inflight_exists=true;
    registers.result=results[i];
    traffic_exit(&registers,TRAFFIC_OP_TCP_RX,false);
    if (inflight_exists) return 1;
    traffic_exit(&registers,TRAFFIC_OP_TCP_RX,false);
}
printf("%llu %llu %llu",(unsigned long long)global_value.rx_bytes,
       (unsigned long long)processes[0].value.counters.rx_bytes,
       (unsigned long long)flows[0].value.rx_bytes);
''')
        self.assertEqual(result, ["1024", "1024", "1024"])

    def test_unresolved_udp_endpoints_keep_all_byte_counters(self):
        result = self.run_source(r'''
struct pt_regs registers={.result=64};
inflight_value.flow=(traffic_flow_key_t){.tgid=10,.tid=11,.process_start_ns=1000,
                                      .flags=TRAFFIC_ENDPOINT_UNKNOWN};
inflight_exists=true;
traffic_exit(&registers,TRAFFIC_OP_UDP4_TX,true);
printf("%llu %llu %llu %llu",(unsigned long long)global_value.tx_bytes,
       (unsigned long long)processes[0].value.counters.tx_bytes,
       (unsigned long long)flows[0].value.tx_bytes,
       (unsigned long long)stats[TRAFFIC_STAT_UDP_ENDPOINT_MISS]);
''')
        self.assertEqual(result, ["64", "64", "64", "1"])

    def test_failed_process_name_read_uses_thread_name(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11,.process_start_ns=1000,.comm="worker"};
fail_comm=true;
traffic_account(&flow,128,false);
printf("%s %llu",processes[0].value.comm,
       (unsigned long long)processes[0].value.counters.rx_bytes);
''')
        self.assertEqual(result, ["worker", "128"])

    def test_optional_process_name_core_fields_are_guarded(self):
        result = self.run_source(r'''
traffic_flow_key_t flow={.tgid=10,.tid=11,.process_start_ns=1000,.comm="worker"};
fields_exist=false;
traffic_account(&flow,128,false);
printf("%s %llu",processes[0].value.comm,
       (unsigned long long)processes[0].value.counters.rx_bytes);
''')
        self.assertEqual(result, ["worker", "128"])

    def test_flow_entry_carries_process_identity_for_tcp_and_udp(self):
        result = self.run_source(r'''
struct inet_sock socket={.common={.skc_family=AF_INET,.skc_num=12345,
                                .skc_dport=htons(443)}};
traffic_flow_key_t tcp={},udp={},missing={};
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_TCP,0,&tcp));
printf("%u %u %u %u %llu ",tcp.tgid,tcp.tid,tcp.lport,tcp.rport,
       (unsigned long long)tcp.process_start_ns);
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_UDP,AF_INET,&udp));
printf("%u %llu ",udp.flags,(unsigned long long)udp.process_start_ns);
fail_start=true;
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_TCP,0,&missing));
printf("%llu",(unsigned long long)missing.process_start_ns);
''')
        self.assertEqual(result, ["0", "10", "11", "12345", "443", "1000",
                                  "0", "1", "1000", "0", "0"])

    def test_existing_protocol_thread_uid_and_family_filters_are_preserved(self):
        result = self.run_source(r'''
struct inet_sock socket={.common={.skc_family=AF_INET}};
traffic_flow_key_t flow={};
traffic_config.protocol=IPPROTO_UDP;
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_TCP,0,&flow));
traffic_config.protocol=0;traffic_config.tid=12;
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_TCP,0,&flow));
traffic_config.tid=11;traffic_config.uid_enabled=true;traffic_config.uid=999;
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_TCP,0,&flow));
traffic_config.uid=1000;
printf("%d ",traffic_fill_key((struct sock *)&socket,IPPROTO_UDP,AF_INET6,&flow));
printf("%d",traffic_fill_key((struct sock *)&socket,IPPROTO_UDP,AF_INET,&flow));
''')
        self.assertEqual(result, ["-1", "-1", "-1", "-1", "0"])


if __name__ == "__main__":
    unittest.main()
