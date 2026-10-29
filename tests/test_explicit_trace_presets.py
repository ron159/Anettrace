"""Generated presets must not turn optional probes into explicit user requests."""
import re
import unittest

from tests import test_flow_identity as helpers

ROOT = helpers.ROOT
function = helpers.function


class ExplicitTracePresetTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def capture_helpers(self):
        source = (ROOT / 'src/trace.c').read_text()
        header = (ROOT / 'src/trace.h').read_text()
        pseudo = function(source, 'trace_prepare_pesudo')
        names = set(re.findall(r'&trace_(\w+)', pseudo))
        names.add('tcp_ack_update_rtt')
        for preset in ('perfetto_compact_traces', 'connect_diagnostic_traces'):
            initializer = re.search(r'static char ' + preset + r'\[\]\s*=\s*(.*?);',
                                    pseudo, re.S).group(1)
            names.update(''.join(re.findall(r'"([^"]*)"', initializer)).split(','))
        names = sorted(names)
        arguments = re.search(r'typedef struct trace_args \{.*?\} trace_args_t;',
                              header, re.S).group()
        code = r'''
#include <errno.h>
#define TRACE_ENABLE (1U << 1)
#define TRACE_INVALID (1U << 2)
#define TRACE_RET (1U << 3)
#define TRACE_STACK (1U << 4)
#define TRACE_CFREE (1U << 7)
#define TRACE_EXPLICIT (1U << 8)
#define FUNC_STATUS_RX 1
#define FUNC_STATUS_TX 2
#define FUNC_STATUS_MATCHER 4
#define FUNC_STATUS_CFREE 8
#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
enum { TRACE_MODE_TIMELINE, TRACE_MODE_BASIC, TRACE_MODE_DIAG, TRACE_MODE_SOCK,
       TRACE_MODE_MONITOR, TRACE_MODE_DROP, TRACE_MODE_RTT, TRACE_MODE_LATENCY };
#define TRACE_MODE_BPF_CTX_MASK ((1U<<TRACE_MODE_TIMELINE)|(1U<<TRACE_MODE_DIAG)|(1U<<TRACE_MODE_LATENCY))
typedef struct { char name[64]; unsigned index, status, monitor; bool def; } trace_t;
typedef struct { int unused; } trace_group_t;
typedef struct {
    bool perfetto, detail, latency_summary, drop_reason, network_socket_filter,
         has_filter, uid_enabled, match_mode, latency_free;
    unsigned rate_limit, __rate_limit, netns, pid, uid, latency_min, first_rtt,
             last_rtt, trace_mode, max_event;
    struct { unsigned pkt_len_1, pkt_len_2, tcp_flags; } pkt;
} bpf_args_t;
''' + arguments + r'''
static struct {
    trace_args_t args;
    bpf_args_t bpf_args;
    unsigned mode, mode_mask;
    bool detail, skip_last, drop_reason, reset_reason;
} trace_ctx;
''' + '\n'.join('static trace_t trace_' + name + ';' for name in names) + '\n'
        code += 'static trace_t *catalog[] = {' + ','.join('&trace_' + name for name in names) + '};\n'
        code += r'''
#define trace_for_each(trace) \
    for (unsigned item=0; item<ARRAY_SIZE(catalog) && ((trace)=catalog[item]); item++)
static void trace_set_enable(trace_t *trace) { trace->status |= TRACE_ENABLE; }
static int trace_set_stack(trace_t *trace) { trace->status |= TRACE_STACK; return 0; }
static void trace_set_status(unsigned index, unsigned status) { (void)index; (void)status; }
static void trace_set_ret(trace_t *trace) { trace->status |= TRACE_RET; }
static void trace_set_invalid_reason(trace_t *trace, const char *reason) {
    (void)reason; trace->status |= TRACE_INVALID;
}
''' + function(source, 'trace_set_target') + function(source, 'trace_enable')
        code += r'''
static trace_group_t all;
static trace_group_t *search_trace_group(char *name) {
    return !strcmp(name,"all") ? &all : NULL;
}
/* Catalogue traversal is controlled; actual selection and parsing run below. */
static int __trace_group_enable(trace_group_t *group, int target) {
    (void)group;
    trace_t *trace;
    trace_for_each(trace) {
        int error=trace_set_target(trace,target);
        if (error) return error;
    }
    return 0;
}
''' + function(source, 'trace_group_enable') + function(source, 'trace_parse_traces')
        code += pseudo + r'''
static void trace_enable_default(void) {}
static bool debugfs_mounted(void) { return true; }
static bool drop_reason_support(void) { return false; }
static bool reset_reason_support(void) { return false; }
static const char *get_drop_reason(int value) { (void)value; return NULL; }
static const char *get_reset_reason(int value) { (void)value; return NULL; }
static bool trace_has_pkt_filter(void) { return true; }
static void trace_enable_perfetto_output(void) {}
static bool mode_has_context(void) { return true; }
static int trace_prepare_mode(trace_args_t *args) { (void)args; return 0; }
static void trace_check_sock_skb(void) {}
static unsigned file_inode(const char *path) { (void)path; return 1; }
static int parse_tcp_flasg(char *flags) { (void)flags; return 0; }
static int trace_check_force(void) { return 0; }
''' + function(source, 'trace_prepare_args')
        initialization = '\n'.join(
            f'strcpy(trace_{name}.name,"{name}"); trace_{name}.index={index};'
            for index, name in enumerate(names))
        return code, initialization

    def selected(self, setup, names):
        code, initialization = self.capture_helpers()
        body = initialization + '\ntrace_ctx.args.perfetto_events="fixture.jsonl";\n'
        body += setup + '\nprintf("%d ", trace_prepare_args());\n'
        body += '\n'.join(
            f'printf("%d ", !!(trace_{name}.status & TRACE_EXPLICIT));' for name in names)
        return self.run_source(code, body)

    def test_default_compact_preset_is_optional(self):
        self.assertEqual(self.selected('', ['ip_output', 'tcp_sendmsg', 'consume_skb']),
                         ['0', '0', '0', '0'])

    def test_default_connect_preset_is_not_a_named_user_request(self):
        self.assertEqual(self.selected('trace_ctx.args.connect_diagnostics=true;',
                                       ['inet_stream_connect', 'tcp_close', 'sk_alloc']),
                         ['0', '0', '0', '0'])

    def test_default_detailed_group_remains_optional(self):
        self.assertEqual(self.selected('trace_ctx.args.trace_detail=true;',
                                       ['ip_output', 'tcp_sendmsg']), ['0', '0', '0'])

    def test_named_user_trace_remains_explicit(self):
        self.assertEqual(self.selected('trace_ctx.args.traces="ip_output";',
                                       ['ip_output', 'tcp_sendmsg']), ['0', '1', '0'])

    def test_default_preset_preserves_named_stack_and_matcher_requests(self):
        self.assertEqual(self.selected(
            'trace_ctx.args.traces_stack="ip_output";\n'
            'trace_ctx.args.trace_matcher="tcp_sendmsg";',
            ['ip_output', 'tcp_sendmsg', 'consume_skb']), ['0', '1', '1', '0'])

    def test_default_preset_preserves_named_free_request(self):
        self.assertEqual(self.selected('trace_ctx.args.trace_free="consume_skb";',
                                       ['consume_skb', 'ip_output']), ['0', '1', '0'])


if __name__ == '__main__':
    unittest.main()
