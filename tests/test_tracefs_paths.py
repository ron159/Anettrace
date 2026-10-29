"""Exercise actual tracing path consumers against isolated filesystem fixtures."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = "/sys/kernel/debug/tracing"
MODERN = "/sys/kernel/tracing"


def function(source, name):
    # C function closing braces are unindented. Unlike counting brace bytes,
    # this also handles the literal "{" in the real format-file parsers.
    match = re.search(r"^[^\n]*\b" + name + r"\([^;]*?\n\{", source, re.M)
    if not match:
        raise AssertionError("Missing source function: " + name)
    return source[match.start():source.index('\n}', match.end()) + 2] + '\n'

PRELUDE = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
static const char *fixture_root;
static void fixture_path(char *result, size_t size, const char *path) {
    snprintf(result, size, "%s%s", fixture_root, path);
}
static bool file_exist(const char *path) {
    char mapped[1024];
    fixture_path(mapped, sizeof(mapped), path);
    return access(mapped, F_OK) == 0;
}
static FILE *fixture_fopen(const char *path, const char *mode) {
    char mapped[1024];
    fixture_path(mapped, sizeof(mapped), path);
    return fopen(mapped, mode);
}
/* The shell is a boundary: inspect the same real fixture file as cat/grep. */
static int simple_exec(char *command) {
    if (strstr(command, "mount | grep debugfs"))
        return !file_exist("/sys/kernel/debug/tracing/events");
    char path[512], line[1024];
    if (strstr(command, "kprobe_events")) {
        char kind, target[128], name[128];
        if (sscanf(command, "(echo '%c:%127s %127[^']' >> %511[^)])",
                   &kind, target, name, path) != 4)
            return 1;
        if (!file_exist(path)) return 1;
        FILE *stream = fixture_fopen(path, "a");
        if (!stream) return 1;
        fprintf(stream, "%c:%s %s\n", kind, target, name);
        fclose(stream);
        char *suffix = strstr(path, "/kprobe_events");
        if (!suffix) return 1;
        snprintf(suffix, sizeof(path) - (suffix - path),
                 "/events/kprobes/%s/id", target);
        stream = fixture_fopen(path, "w");
        if (!stream) return 1;
        fputs("333\n", stream);
        fclose(stream);
        return 0;
    }
    if (sscanf(command, "cat %511s", path) != 1)
        return 1;
    FILE *stream = fixture_fopen(path, "r");
    if (!stream) return 1;
    int result = 1;
    while (fgets(line, sizeof(line), stream))
        if (strstr(line, "NOT_SPECIFIED")) result = 0;
    fclose(stream);
    return result;
}
static int execf(char *output, char *format, ...) {
    (void)output;
    char command[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(command, sizeof(command), format, args);
    va_end(args);
    return simple_exec(command);
}
#define fopen fixture_fopen
#define pr_debug(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_verb(...) ((void)0)
'''


class TracefsPathTests(unittest.TestCase):
    def run_source(self, source, body, roots, files=None):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for root in roots:
                (fixture / root.lstrip('/') / 'events').mkdir(parents=True)
            for name, content in (files or {}).items():
                path = fixture / name.lstrip('/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            binary = fixture / 'regression'
            cfile = fixture / 'regression.c'
            cfile.write_text(PRELUDE + source + '\nint main(int argc, char **argv) {\n'
                             '(void)argc; fixture_root = argv[1];\n' + body + '\n}\n')
            result = subprocess.run(
                ['cc', '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function',
                 '-Wno-unused-variable', str(cfile), '-o', str(binary)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary), str(fixture)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.split()

    def path_helper(self):
        source = (ROOT / 'utils/sys_utils.c').read_text()
        # The pre-fix availability check has no path discovery helper.
        return function(source, 'get_tracing_path') if 'get_tracing_path(' in source else ''

    def test_tracing_availability_accepts_standalone_tracefs(self):
        source = self.path_helper() + function(
            (ROOT / 'utils/sys_utils.c').read_text(), 'debugfs_mounted')
        for roots, expected in (([LEGACY], '1'), ([MODERN], '1'),
                                ([LEGACY, MODERN], '1'), ([], '0')):
            with self.subTest(roots=roots):
                self.assertEqual(self.run_source(
                    source, 'printf("%d", debugfs_mounted());', roots), [expected])

    def test_path_discovery_preserves_legacy_preference_and_reports_absence(self):
        source = function((ROOT / 'utils/sys_utils.c').read_text(), 'get_tracing_path')
        for roots, expected in (([LEGACY], LEGACY), ([MODERN], MODERN),
                                ([LEGACY, MODERN], LEGACY), ([], 'unavailable')):
            with self.subTest(roots=roots):
                self.assertEqual(self.run_source(source, r'''
const char *path = get_tracing_path();
printf("%s", path ? path : "unavailable");
''', roots), [expected])

    def test_drop_and_reset_reasons_use_the_selected_mount(self):
        fsearch = function((ROOT / 'utils/sys_utils.c').read_text(), 'fsearch')
        for kind, file, event, prefix in (
                ('drop', 'src/dropreason.c', 'skb/kfree_skb', ''),
                ('reset', 'src/rstreason.c', 'tcp/tcp_send_reset',
                 '__print_symbolic state, { 1, "ESTABLISHED" } ')):
            original = (ROOT / file).read_text()
            source = self.path_helper() + fsearch + f'''
#define REASON_MAX_COUNT 256
#define REASON_MAX_LEN 32
static char {kind}_reasons[REASON_MAX_COUNT][REASON_MAX_LEN];
static int {kind}_reason_max;
static bool {kind}_reason_inited;
''' + ''.join(function(original, name) for name in (
                f'{kind}_reason_support', 'parse_reason_enum', f'get_{kind}_reason'))
            for roots in ([LEGACY], [MODERN], [LEGACY, MODERN], []):
                files = {f'{root}/events/{event}/format':
                         prefix + '__print_symbolic reason, { 1, "NOT_SPECIFIED" } '
                         '{ 2, "TEST_REASON" }\n' for root in roots}
                with self.subTest(kind=kind, roots=roots):
                    result = self.run_source(source, f'''
const char *reason = get_{kind}_reason(2);
printf("%d %s", {kind}_reason_support(), reason ? reason : "unavailable");
''', roots, files)
                    self.assertEqual(result, ['1', 'TEST_REASON'] if roots
                                     else ['0', 'unavailable'])

    def test_tracepoint_preparation_uses_tracefs_without_disabling_functions(self):
        source = self.path_helper() + r'''
typedef struct { bool invalid, enabled, is_func; char name[128];
    const char *tp; unsigned status; } trace_t;
static trace_t traces[] = {
    {.enabled=true, .tp="skb/kfree_skb"},
    {.enabled=true, .is_func=true, .name="tcp_sendmsg"},
};
static int prepared;
static void record_prepared(void) { prepared++; }
static struct { void (*prepare_traces)(void); } ops = {record_prepared};
static struct { int mode; typeof(ops) *ops; } trace_ctx = {.ops=&ops};
#define TRACE_MODE_BPF_CTX_MASK 0
#define TRACE_ATTACH_MANUAL 1
#define TRACE_EXPLICIT (1U << 8)
#define TRACE_SYMBOL_AMBIGUOUS (1U << 9)
#define SYM_NOT_EXIST 0
#define SYM_MODULE 1
#define SYM_KERNEL 2
#define SYM_AMBIGUOUS 3
#define trace_for_each(trace) for (trace=traces; trace<traces+2; trace++)
static bool trace_is_invalid(trace_t *trace) { return trace->invalid; }
static bool trace_is_enable(trace_t *trace) { return trace->enabled; }
static bool trace_is_func(trace_t *trace) { return trace->is_func; }
static void trace_set_invalid(trace_t *trace) { trace->invalid=true; }
static void trace_set_invalid_reason(trace_t *trace, const char *reason) {
    (void)reason; trace_set_invalid(trace);
}
static void trace_group_enable(const char *group, int value) { (void)group; (void)value; }
static void trace_exec_cond(void) {}
static void trace_prepare_status(void) {}
static int sym_get_type(const char *name) { (void)name; return 1; }
static int sym_search_unique(const char *name, char *result, size_t size, bool partial) {
    (void)partial; snprintf(result, size, "%s", name); return SYM_KERNEL;
}
static int sym_search_pattern(const char *name, char *result, bool partial) {
    (void)name; (void)result; (void)partial; return SYM_NOT_EXIST;
}
''' + ''.join(function((ROOT / 'src/trace.c').read_text(), name)
              for name in ('trace_resolve_symbol', 'trace_prepare_traces'))
        for roots in ([LEGACY], [MODERN], [LEGACY, MODERN], []):
            files = {f'{root}/events/skb/kfree_skb/format': 'fixture' for root in roots}
            with self.subTest(roots=roots):
                result = self.run_source(source, r'''
int status = trace_prepare_traces();
printf("%d %d %d %d", status, traces[0].invalid, traces[1].invalid, prepared);
''', roots, files)
                self.assertEqual(result, ['0', '0', '0', '1'] if roots
                                 else [str(-2), '0', '0', '0'])

    def test_compat_kprobe_reads_and_creates_events_on_the_selected_mount(self):
        source = self.path_helper() + r'''
struct perf_event_attr { int type, sample_type, sample_period, wakeup_events;
    unsigned long long config; };
#define PERF_TYPE_TRACEPOINT 2
#define PERF_SAMPLE_RAW 1
#define SYS_perf_event_open 10
#define PERF_EVENT_IOC_ENABLE 20
#define PERF_EVENT_IOC_SET_BPF 21
static int event_id, attached_program, enabled;
static int fixture_open(const char *path, int flags, ...) {
    char mapped[1024];
    fixture_path(mapped, sizeof(mapped), path);
    return open(mapped, flags);
}
static long fixture_syscall(long number, struct perf_event_attr *attr, ...) {
    (void)number; event_id = attr->config; return 99;
}
static int fixture_ioctl(int fd, unsigned long request, int argument) {
    (void)fd;
    if (request == PERF_EVENT_IOC_ENABLE) enabled++;
    if (request == PERF_EVENT_IOC_SET_BPF) attached_program = argument;
    return 0;
}
#define open fixture_open
#define syscall fixture_syscall
#define ioctl fixture_ioctl
''' + function((ROOT / 'utils/bpf_utils.c').read_text(), 'compat_bpf_attach_kprobe')
        for roots in ([LEGACY], [MODERN], [LEGACY, MODERN], []):
            for create in (False, True):
                files = {}
                for index, root in enumerate(roots):
                    files[f'{root}/kprobe_events'] = ''
                    files[f'{root}/events/kprobes/ret_tcp_sendmsg_isra_0/.keep'] = ''
                    if not create:
                        files[f'{root}/events/kprobes/ret_tcp_sendmsg_isra_0/id'] = str(111 + index)
                with self.subTest(roots=roots, create=create):
                    result = self.run_source(source, r'''
int status = compat_bpf_attach_kprobe(55, "tcp_sendmsg.isra.0", true);
printf("%d %d %d %d", status, event_id, enabled, attached_program);
''', roots, files)
                    self.assertEqual(result, ['0', '333' if create else '111', '1', '55']
                                     if roots else ['-1', '0', '0', '0'])


if __name__ == '__main__':
    unittest.main()
