"""Perf buffer policy accounts for page size and preserves terminal defaults."""
import unittest
import os
from pathlib import Path
import subprocess
import sys

from tests import test_flow_identity as helpers


class CaptureBufferTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def test_unfiltered_force_detail_gets_burst_capacity_and_override_wins(self):
        source = (helpers.ROOT / "src/trace.c").read_text()
        code = r'''
#define CAPTURE_QUEUE_BYTES (32U * 1024 * 1024)
static struct {
    struct { bool force, trace_detail; u32 capture_queue_mib; } args;
    struct { bool has_filter; } bpf_args;
} trace_ctx;
''' + helpers.function(source, "trace_capture_queue_bytes")
        result = self.run_source(code, r'''
printf("%zu ",trace_capture_queue_bytes()/(1024*1024));
trace_ctx.args.force = true;
printf("%zu ",trace_capture_queue_bytes()/(1024*1024));
trace_ctx.args.trace_detail = true;
printf("%zu ",trace_capture_queue_bytes()/(1024*1024));
trace_ctx.bpf_args.has_filter = true;
printf("%zu ",trace_capture_queue_bytes()/(1024*1024));
trace_ctx.args.capture_queue_mib = 1;
printf("%zu",trace_capture_queue_bytes()/(1024*1024));
''')
        self.assertEqual(result, ["32", "32", "256", "32", "1"])

    def test_capture_uses_larger_buffer_and_explicit_size_wins(self):
        source = (helpers.ROOT / "src/trace.c").read_text()
        code = r'''
#define _SC_PAGESIZE 0
static long page_size = 4096;
static long sysconf(int name) { (void)name; return page_size; }
static struct {
    struct { bool capture_trace; char *perfetto_events; u32 perf_buffer_pages; } args;
} trace_ctx;
''' + helpers.function(source, "trace_perf_buffer_pages")
        result = self.run_source(code, r'''
printf("%zu ", trace_perf_buffer_pages());
trace_ctx.args.capture_trace = true;
printf("%zu ", trace_perf_buffer_pages());
trace_ctx.args.capture_trace = false;
trace_ctx.args.perfetto_events = "capture.jsonl";
printf("%zu ", trace_perf_buffer_pages());
page_size = 16384;
printf("%zu ", trace_perf_buffer_pages());
page_size = 65536;
printf("%zu ", trace_perf_buffer_pages());
trace_ctx.args.perf_buffer_pages = 512;
printf("%zu", trace_perf_buffer_pages());
''')
        self.assertEqual(result, ["1024", "4096", "4096", "1024", "256", "512"])

    @unittest.skipUnless(sys.platform == "linux", "Linux CLI binary required")
    def test_cli_rejects_invalid_page_counts_before_loading_bpf(self):
        binary = Path(os.environ.get("ANETTRACE_TEST_BIN", helpers.ROOT / "src/anettrace"))
        if not binary.is_file():
            self.skipTest("CLI binary not built")
        for pages in ("0", "32", "65", "16385", "32768", "-1"):
            with self.subTest(pages=pages):
                result = subprocess.run([str(binary), "--perf-buffer-pages", pages],
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--perf-buffer-pages must be a power of two", result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform == "linux", "Linux CLI binary required")
    def test_cli_rejects_invalid_queue_size_and_mode(self):
        binary = Path(os.environ.get("ANETTRACE_TEST_BIN", helpers.ROOT / "src/anettrace"))
        if not binary.is_file():
            self.skipTest("CLI binary not built")
        for args in (("--capture-queue-mib", "32"),
                     ("--capture-trace", "--capture-queue-mib", "0"),
                     ("--capture-trace", "--capture-queue-mib", "513"),
                     ("--capture-trace", "--capture-queue-mib", "-1")):
            with self.subTest(args=args):
                result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--capture-queue-mib requires", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
