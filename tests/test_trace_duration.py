"""Event-loss callbacks must not shorten a timed Perfetto capture."""
import errno
import unittest

from tests import test_flow_identity as helpers


class TraceDurationTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def test_pending_rx_never_reaches_terminal_output(self):
        source = (helpers.ROOT / "src/trace.c").read_text()
        code = r'''
#define FUNC_TYPE_FUNC 0
#define FUNC_TYPE_TRACING_RET 3
typedef struct { u16 meta; } event_t;
typedef struct { u16 meta; u8 owner_pending; } detail_event_t;
static unsigned exported, printed;
static bool capture_async;
static void capture_queue_event(void *data, int cpu, u32 size) {
    (void)data; (void)cpu; (void)size; exported++;
}
static bool stopped;
static bool trace_stopped(void) { return stopped; }
static void perfetto_export_event(void *data, int cpu, u32 size) {
    (void)data; (void)cpu; (void)size; exported++;
}
static void terminal(void *ctx, int cpu, void *data, u32 size) {
    (void)ctx; (void)cpu; (void)data; (void)size; printed++;
}
static struct { void (*trace_poll)(void *,int,void *,u32); } ops = {terminal};
static struct { typeof(ops) *ops; } trace_ctx = {&ops};
''' + helpers.function(source, "poll_handler_wrap")
        result = self.run_source(code, r'''
detail_event_t pending={.meta=FUNC_TYPE_FUNC,.owner_pending=1};
poll_handler_wrap(NULL,0,&pending,sizeof(pending));
printf("%u %u ",exported,printed);
pending.meta=FUNC_TYPE_TRACING_RET;
poll_handler_wrap(NULL,0,&pending,sizeof(pending));
printf("%u %u ",exported,printed);
pending.owner_pending=0;
poll_handler_wrap(NULL,0,&pending,sizeof(pending));
printf("%u %u ",exported,printed);
stopped = true;
capture_async = true;
poll_handler_wrap(NULL,0,&pending,sizeof(pending));
printf("%u %u",exported,printed);
''')
        self.assertEqual(result, ["1", "0", "2", "0", "3", "1", "4", "1"])

    def test_ready_is_emitted_only_after_buffer_creation_and_before_poll(self):
        source = (helpers.ROOT / "src/trace.c").read_text()
        code = r'''
#include <errno.h>
#include <time.h>
#include <unistd.h>
#define LIBBPF_MAJOR_VERSION 1
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
#define CAPTURE_QUEUE_BYTES 32768
#define BPF_ANY 0
struct perf_buffer { int unused; } buffer;
static int buffer_error, queue_error, map_result = 3, released, poll_result, consume_result;
static bool capture_async;
static size_t trace_perf_buffer_pages(void) { return 4096; }
static size_t trace_capture_queue_bytes(void) { return CAPTURE_QUEUE_BYTES; }
static int capture_queue_start(size_t size) { (void)size; printf("queue "); return queue_error; }
static void capture_queue_tick(void) { printf("tick "); }
static void capture_queue_stop(void) { printf("drained "); }
static void trace_capture_stop(void) { printf("system-stop "); }
static void perfetto_export_mark_capture_end(void) { printf("cutoff "); }
static int trace_disable_capture(void) { printf("disable "); return 0; }
static int perf_buffer__consume(struct perf_buffer *p) { (void)p; printf("consume "); return consume_result; }
static void ready(void) { printf("enable "); }
static int raw_poll(void) { printf("raw "); return 0; }
static struct { void (*trace_ready)(void); int (*raw_poll)(void); } ops = {ready, NULL};
static struct {
    struct { unsigned duration, capture_queue_mib; bool ring_buffer, traffic_ui, capture_trace; } args;
    typeof(ops) *ops;
    void *obj;
} trace_ctx = {.ops = &ops};
static u64 poll_deadline_ns;
static int bpf_object__find_map_fd_by_name(void *obj, const char *name) {
    (void)obj; (void)name; return map_result;
}
#define poll_handler_wrap NULL
#define trace_on_lost NULL
static struct perf_buffer *perf_buffer__new(int fd, int pages, void *sample,
        void *lost, void *ctx, void *opts) {
    (void)fd; (void)pages; (void)sample; (void)lost; (void)ctx; (void)opts;
    printf("buffer "); return &buffer;
}
static int libbpf_get_error(void *p) { (void)p; return buffer_error; }
static int perf_buffer__poll(struct perf_buffer *p, int timeout) {
    (void)p; (void)timeout; printf("poll "); return poll_result;
}
static void perf_buffer__free(struct perf_buffer *p) { (void)p; released++; }
static void perfetto_export_tick(void) {}
static int poll_timeout(int err) { (void)err; return 1; }
''' + helpers.function(source, "trace_poll")
        result = self.run_source(code, r'''
printf("%d ", trace_poll());
trace_ctx.args.capture_trace = true;
printf("%d ", trace_poll());
poll_result = -EINTR;
consume_result = -EIO;
printf("%d ", trace_poll());
poll_result = consume_result = 0;
queue_error = -EAGAIN;
printf("%d ", trace_poll());
buffer_error = -ENOMEM;
printf("%d ", trace_poll());
map_result = -ENOENT;
printf("%d ", trace_poll());
ops.raw_poll = raw_poll;
printf("%d %d", trace_poll(), released);
''')
        self.assertEqual(result, ["buffer", "enable", "poll", "0",
                                  "buffer", "queue", "enable", "poll", "tick",
                                  "disable", "consume", "system-stop", "cutoff", "drained", "0",
                                  "buffer", "queue", "enable", "poll",
                                  "disable", "consume", "system-stop", "cutoff", "drained", "-5",
                                  "buffer", "queue", str(-errno.EAGAIN), "buffer", "-12", "-2",
                                  "enable", "raw", "0", "4"])

    def run_capture(self, mode, ring=False):
        source = (helpers.ROOT / "src/trace.c").read_text()
        code = r'''
#include <time.h>
#include <unistd.h>
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
static struct {
    bool stop;
    struct {
        bool capture_trace, ring_buffer, traffic;
        char *perfetto_events;
        u32 duration, count;
    } args;
} trace_ctx;
static u64 lost_events, now_ns, poll_deadline_ns;
static bool capture_async;
static void capture_queue_lost(int cpu, u64 count) { (void)cpu; lost_events += count; }
static void perfetto_export_lost(int cpu, u64 count) {
    (void)cpu;
    lost_events += count;
}
static void trace_stop(void) { trace_ctx.stop = true; }
static int capture_clock_gettime(clockid_t clock, struct timespec *now) {
    (void)clock;
    now->tv_sec = now_ns / 1000000000ULL;
    now->tv_nsec = now_ns % 1000000000ULL;
    return 0;
}
#define clock_gettime capture_clock_gettime
static int traffic_poll(void) { return 0; }
static struct { u64 event_count; } bpf_args;
#define get_bpf_args() (&bpf_args)
''' + helpers.function(source, "trace_on_lost")
        code += helpers.function(source, "poll_timeout")
        return self.run_source(code, f'''
trace_ctx.args.capture_trace = {int(mode == 'capture')};
trace_ctx.args.perfetto_events = {'"events.jsonl"' if mode == 'events' else 'NULL'};
trace_ctx.args.ring_buffer = {int(ring)};
trace_ctx.args.duration = 30;
poll_deadline_ns = 130ULL * 1000000000ULL;
now_ns = 110ULL * 1000000000ULL;
trace_on_lost(NULL, 2, 7);
trace_on_lost(NULL, 3, 5);
printf("%d %llu %d ", trace_ctx.stop, lost_events, poll_timeout(0));
now_ns = 129999999999ULL;
printf("%d ", poll_timeout(0));
now_ns = poll_deadline_ns;
printf("%d ", poll_timeout(0));
trace_ctx.stop = true;
printf("%d", poll_timeout(0));
''')

    def test_capture_and_jsonl_keep_running_until_thirty_seconds_after_loss(self):
        for mode in ("capture", "events"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_capture(mode), ["0", "12", "0", "0", "1", "1"])

    def test_ring_capture_keeps_running_past_window_until_interrupted(self):
        self.assertEqual(self.run_capture("capture", ring=True), ["0", "12", "0", "0", "0", "1"])

    def test_terminal_trace_preserves_stop_on_loss(self):
        self.assertEqual(self.run_capture("terminal"), ["1", "12", "1", "1", "1", "1"])


if __name__ == "__main__":
    unittest.main()
