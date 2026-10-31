"""Run the native system-only capture path with a controllable Perfetto child."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]

FAKE_PERFETTO = r'''
import os, re, signal, sys, time
args = sys.argv[1:]
legacy = os.environ.get("FAKE_LEGACY") == "1"
if args == ["--help"]:
    with open(os.environ["PROBE_PID_LOG"], "w") as log:
        log.write(str(os.getpid()))
    if os.environ.get("FAKE_MODE") == "help-fail":
        sys.exit(7)
    if os.environ.get("FAKE_MODE") == "help-hang":
        time.sleep(60)
    if os.environ.get("FAKE_MODE") == "help-invalid":
        print("unrecognized help option", file=sys.stderr)
        sys.exit(1)
    print("--txt -c CONFIG -o TRACE" + ("" if legacy else " --notify-fd FD"), file=sys.stderr)
    sys.exit(1)  # Perfetto normally returns 1 after printing --help.
notify_fd = None
if args[:1] == ["--notify-fd"]:
    if legacy:
        print("perfetto: unrecognized option '--notify-fd'", file=sys.stderr)
        sys.exit(2)
    notify_fd = int(args[1])
    args = args[2:]
assert len(args) == 5 and args[:2] == ["--txt", "-c"] and args[3] == "-o"
config = sys.stdin.read() if args[2] == "-" else open(args[2]).read()
# Simulate a ROM which permits Perfetto only in its labelled directories.
if "PERFETTO_TEST_ROOT" in os.environ:
    root = os.environ["PERFETTO_TEST_ROOT"]
    assert args[2].startswith(root + "/configs/")
    assert args[4].startswith(root + "/traces/")
    assert not os.path.exists(args[4]), "shell must not pre-create the trace"
trace = sys.stdout.buffer if args[4] == "-" else open(args[4], "wb")
with open(os.environ["CONFIG_LOG"], "w") as log:
    log.write(config)
with open(os.environ["PID_LOG"], "w") as log:
    log.write(str(os.getpid()))
durations = re.findall(r"^duration_ms:\s*(\d+)", config, re.M)
expires = time.monotonic() + int(durations[-1]) / 1000 if durations else float("inf")
def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)
def emit():
    # A timestamped TracePacket, using the monotonic clock.
    packet = b"\x40" + varint(time.monotonic_ns()) + b"\x58\x03"
    if os.environ.get("TRIM_EVENTS"):
        packet = (b"\x40" + varint(time.clock_gettime_ns(time.CLOCK_MONOTONIC)) + b"\xd0\x03\x03"
                  + b"\x5a\x02\x48\x03")  # monotonic TrackEvent instant
    trace.write(b"\x0a" + varint(len(packet)) + packet)
    trace.flush()
def stop(*args):
    if os.environ.get("SLOW_STOP"):
        until = time.monotonic() + 6
        while time.monotonic() < until:
            emit()
            time.sleep(0.1)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
mode = os.environ.get("FAKE_MODE")
if mode == "early-fail":
    sys.exit(7)
if mode == "delayed-ready":
    ready_at = time.monotonic() + 1.25
    while time.monotonic() < ready_at:
        if time.monotonic() >= expires:
            sys.exit(0)
        time.sleep(0.01)
if notify_fd is not None and mode != "no-ack":
    os.write(notify_fd, b"\x01" if mode == "bad-ack" else b"0" if mode == "ascii-ack" else b"\x00")
    os.close(notify_fd)
if os.environ.get("FAKE_MODE") == "fail":
    emit()
    time.sleep(0.4)
    sys.exit(7)
if os.environ.get("FAKE_MODE") == "empty":
    time.sleep(0.4)
    sys.exit(0)
while True:
    if time.monotonic() >= expires:
        sys.exit(0)
    emit()
    time.sleep(0.05)
'''

DRIVER = r'''
/* Only trace_capture.c uses the test poll shim; the driver calls real poll. */
#undef poll
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "trace_capture.h"
/* Shell may read/unlink traces but SELinux forbids creating files there.
 * The separately executed fake Perfetto is not subject to this shim.
 */
int open(const char *path, int flags, ...) {
    const char *root = getenv("PERFETTO_TEST_ROOT");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
        if (root && !strncmp(path, root, strlen(root)) &&
            !strncmp(path + strlen(root), "/traces/", 8)) {
            errno = EACCES;
            return -1;
        }
    }
    return openat(AT_FDCWD, path, flags, mode);
}
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }
int capture_test_poll(struct pollfd *fds, nfds_t count, int timeout) {
    const char *short_timeout = getenv("CAPTURE_TEST_READY_TIMEOUT_MS");
    if (short_timeout && timeout == 30000) {
        FILE *log = fopen(getenv("CAPTURE_TEST_POLL_LOG"), "w");
        if (!log) return -1;
        fprintf(log, "%d\n", timeout);
        fclose(log);
        timeout = atoi(short_timeout);
    }
    return poll(fds, count, timeout);
}
int main(int argc, char **argv) {
    int combined = getenv("COMBINED") != NULL;
    if (argc != 5) return 2;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    if (trace_capture_start(argv[1], atoi(argv[2]), "sched",
                            argv[4][0] ? argv[4] : NULL,
                            atoi(argv[3]), !combined)) return 1;
    if (getenv("FINISH_DELAY")) {
        sleep(atoi(argv[2]));
        trace_capture_stop();
        sleep(2); /* Simulate draining a large native export queue. */
        return trace_capture_finish() ? 1 : 0;
    }
    if (combined) {
        FILE *network = fopen(trace_capture_network_path(), "wb");
        if (!network) return 3;
        fputs("network", network);
        fclose(network);
        sleep(atoi(argv[2]));
        if (getenv("FAIL_MERGE")) {
            FILE *existing=fopen(argv[1],"wb");
            if (!existing) return 4;
            fputs("keep",existing); fclose(existing);
        }
        trace_capture_stop();
        int result=trace_capture_finish();
        if (getenv("ABORT_AFTER_FAILURE")) trace_capture_abort();
        return result ? 1 : 0;
    }
    if (trace_capture_network_path() != NULL) return 3;
    return trace_capture_wait_system(&stopped) ? 1 : 0;
}
'''


class CaptureTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="anettrace-system-build-")
        cls.addClassCleanup(cls.build.cleanup)
        base = Path(cls.build.name)
        (base / "linux").mkdir()
        (base / "linux/types.h").write_text("typedef unsigned int __u32;\n")
        # Isolate logging/types only; compile the actual capture/config/trim code.
        (base / "sys_utils.h").write_text('''
#include <stdio.h>
#define _H_PKT_UTILS
typedef unsigned long long u64;
#define pr_info(...) fprintf(stderr, __VA_ARGS__)
#define pr_warn(...) fprintf(stderr, __VA_ARGS__)
#define pr_err(...) fprintf(stderr, __VA_ARGS__)
''')
        (base / "driver.c").write_text(DRIVER)
        cls.driver = base / "capture"
        cls.combined_driver = cls.driver
        cls.android_driver = base / "capture-android"
        cls.perfetto_root = base / "perfetto-data"
        (cls.perfetto_root / "configs").mkdir(parents=True)
        (cls.perfetto_root / "traces").mkdir()
        cmd = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
               "-Dpoll=capture_test_poll",
               f"-I{base}", f"-I{ROOT / 'src'}"]
        if sys.platform == "darwin":
            cmd += ["-DCLOCK_BOOTTIME=CLOCK_MONOTONIC"]
        for driver in (cls.driver, cls.android_driver):
            target_flags = [
                "-DANETTRACE_ANDROID_TARGET",
                f'-DPERFETTO_CONFIG_DIR="{cls.perfetto_root}/configs"',
                f'-DPERFETTO_TRACE_DIR="{cls.perfetto_root}/traces"',
            ] if driver == cls.android_driver else []
            subprocess.run(cmd + target_flags + [str(base / "driver.c"),
                           str(ROOT / "src/trace_capture.c"),
                           str(ROOT / "src/perfetto_config.c"),
                           str(ROOT / "src/perfetto_trim.c"),
                           "-o", str(driver)], check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="anettrace-system-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        fake = self.base / "perfetto"
        fake.write_text(f"#!{sys.executable}\n" + FAKE_PERFETTO)
        fake.chmod(0o755)
        self.output = self.base / "system.pftrace"
        self.log = self.base / "config.log"
        self.pid_log = self.base / "pid.log"
        self.probe_pid_log = self.base / "probe.pid"
        self.env = dict(os.environ, PATH=f"{self.base}:{os.environ['PATH']}",
                        CONFIG_LOG=str(self.log), PID_LOG=str(self.pid_log),
                        PROBE_PID_LOG=str(self.probe_pid_log))

    def command(self, ring=False, custom="", duration=1):
        return [str(self.driver), str(self.output), str(duration),
                str(int(ring)), str(custom)]

    def run_capture(self, **kwargs):
        return subprocess.run(self.command(**kwargs), env=self.env,
                              capture_output=True, timeout=10)

    def assert_clean(self):
        self.assertEqual(list(self.base.glob("*.tmp")), [])
        for pid_log in (self.pid_log, self.probe_pid_log):
            if pid_log.exists():
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid_log.read_text()), 0)

    def assert_failed_cleanup(self, stderr):
        traces = list(self.base.glob("*.system.tmp")) + list(self.base.glob("*.anettrace.tmp"))
        if "PERFETTO_TEST_ROOT" in self.env:
            traces += list((self.perfetto_root / "traces").glob("*.pftrace"))
        for trace in traces:
            self.assertIn(str(trace).encode(), stderr)
            self.assertIn(f"bytes={trace.stat().st_size}".encode(), stderr)
            self.assertIn(b"grace_ms=30000", stderr)
            trace.unlink()  # Remove only after proving failed-capture evidence survived.
        self.assert_clean()

    def assert_ring_capture(self):
        proc = subprocess.Popen(self.command(ring=True), env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(1.5)
            self.assertIsNone(proc.poll())
            proc.send_signal(signal.SIGINT)
            _, err = proc.communicate(timeout=8)
            self.assertEqual(proc.returncode, 0, err)
            self.assertNotIn("duration_ms:", self.log.read_text())
            self.assertGreater(self.output.stat().st_size, 0)
            self.assert_clean()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()


class SystemOnlyCaptureTest(CaptureTestCase):
    def test_slow_stop_keeps_writing_past_the_old_five_second_timeout(self):
        self.env["SLOW_STOP"] = "1"
        result = subprocess.run(self.command(), env=self.env,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(self.output.stat().st_size, 0)
        self.assert_clean()

    def test_failed_perfetto_keeps_nonempty_system_trace_and_reports_its_size(self):
        self.env["FAKE_MODE"] = "fail"
        result = self.run_capture()
        self.assertNotEqual(result.returncode, 0)
        traces = list(self.base.glob("*.system.tmp"))
        if "PERFETTO_TEST_ROOT" in self.env:
            traces = list((self.perfetto_root / "traces").glob("*.pftrace"))
        self.assertEqual(len(traces), 1, result.stderr)
        self.assertGreater(traces[0].stat().st_size, 0)
        self.assertIn(str(traces[0]).encode(), result.stderr)
        self.assertIn(b"bytes=", result.stderr)
        self.assertFalse(self.output.exists())
        self.assert_failed_cleanup(result.stderr)

    def test_merge_failure_and_repeated_abort_keep_both_original_traces(self):
        self.env.update(COMBINED="1", FAIL_MERGE="1", ABORT_AFTER_FAILURE="1")
        result = subprocess.run([str(self.combined_driver), str(self.output), "1", "0", ""],
                                env=self.env, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"keep")
        network = Path(str(self.output) + ".anettrace.tmp")
        self.assertEqual(network.read_bytes(), b"network")
        system = list(self.base.glob("*.system.tmp"))
        if "PERFETTO_TEST_ROOT" in self.env:
            system = list((self.perfetto_root / "traces").glob("*.pftrace"))
        self.assertEqual(len(system), 1, result.stderr)
        self.assertGreater(system[0].stat().st_size, 0)
        self.assert_failed_cleanup(result.stderr)

    def test_ring_cutoff_is_stop_time_even_when_export_drain_delays_finish(self):
        self.env["FINISH_DELAY"] = "1"
        self.env["TRIM_EVENTS"] = "1"
        result = self.run_capture(ring=True, duration=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(self.output.stat().st_size, 0)
        self.assert_clean()

    def test_waits_for_delayed_binary_ready_ack(self):
        self.env["FAKE_MODE"] = "delayed-ready"
        start = time.monotonic()
        result = self.run_capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - start, 2.25)
        self.assert_clean()

    def test_capability_probe_failure_and_timeout_are_not_legacy(self):
        for mode in ("help-fail", "help-hang", "help-invalid"):
            with self.subTest(mode=mode):
                self.env["FAKE_MODE"] = mode
                result = self.run_capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"failed to query Perfetto capabilities", result.stderr)
                self.assertFalse(self.pid_log.exists())
                self.assertFalse(self.output.exists())
                self.assert_clean()

    def test_interrupt_during_capability_probe_reaps_child(self):
        self.env["FAKE_MODE"] = "help-hang"
        proc = subprocess.Popen(self.command(), env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not self.probe_pid_log.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.probe_pid_log.exists())
            proc.send_signal(signal.SIGINT)
            _, err = proc.communicate(timeout=5)
            self.assertNotEqual(proc.returncode, 0, err)
            self.assertFalse(self.output.exists())
            self.assert_clean()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def test_bad_ack_is_rejected_and_child_is_reaped(self):
        for mode in ("bad-ack", "ascii-ack"):
            with self.subTest(mode=mode):
                self.env["FAKE_MODE"] = mode
                result = self.run_capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assert_failed_cleanup(result.stderr)

    def test_interrupt_during_readiness_aborts_and_reaps_child(self):
        self.env["FAKE_MODE"] = "no-ack"
        proc = subprocess.Popen(self.command(), env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not self.pid_log.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.pid_log.exists())
            proc.send_signal(signal.SIGINT)
            _, err = proc.communicate(timeout=5)
            self.assertNotEqual(proc.returncode, 0, err)
            self.assertFalse(self.output.exists())
            self.assert_failed_cleanup(err)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def test_readiness_timeout_aborts_and_reaps_child(self):
        poll_log = self.base / "ready-poll.log"
        self.env.update(FAKE_MODE="no-ack", CAPTURE_TEST_READY_TIMEOUT_MS="1000",
                        CAPTURE_TEST_POLL_LOG=str(poll_log))
        start = time.monotonic()
        result = subprocess.run(self.command(), env=self.env,
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        # Assert the production deadline, then exercise a real, shorter poll
        # timeout through the same failure and child-cleanup path.
        self.assertEqual(poll_log.read_text(), "30000\n")
        self.assertGreaterEqual(time.monotonic() - start, 1)
        self.assertIn(b"did not acknowledge data-source readiness", result.stderr)
        self.assertFalse(self.output.exists())
        self.assert_failed_cleanup(result.stderr)

    def test_combined_capture_uses_the_same_ready_ack(self):
        self.env["COMBINED"] = "1"
        self.env["FAKE_MODE"] = "delayed-ready"
        result = subprocess.run([str(self.combined_driver), *self.command()[1:]],
                                env=self.env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.read_bytes().endswith(b"network"))
        self.assert_clean()

    def test_legacy_combined_capture(self):
        self.env["COMBINED"] = "1"
        self.env["FAKE_LEGACY"] = "1"
        result = subprocess.run([str(self.combined_driver), *self.command()[1:]],
                                env=self.env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.read_bytes().endswith(b"network"))
        self.assert_clean()

    def test_duration_and_no_network(self):
        start = time.monotonic()
        result = self.run_capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - start, 1)
        self.assertIn("duration_ms: 32000", self.log.read_text())
        self.assertTrue(self.output.read_bytes().startswith(b"\x0a"))
        self.assertNotIn(b"anettrace", self.output.read_bytes())
        self.assert_clean()

    def test_custom_duration_is_overridden(self):
        custom = self.base / "custom.pbtxt"
        custom.write_text('duration_ms: 999999\nbuffers { size_kb: 1024 }\n')
        result = self.run_capture(custom=custom)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("999999", self.log.read_text())
        self.assertIn("duration_ms: 32000", self.log.read_text())
        self.assert_clean()

    def test_legacy_perfetto_without_notify_fd_captures(self):
        self.env["FAKE_LEGACY"] = "1"
        result = self.run_capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"without data-source readiness", result.stderr)
        self.assertTrue(self.output.read_bytes().startswith(b"\x0a"))
        self.assert_clean()

    def test_legacy_custom_config(self):
        self.env["FAKE_LEGACY"] = "1"
        custom = self.base / "custom.pbtxt"
        custom.write_text('duration_ms: 999999\nbuffers { size_kb: 1024 }\n')
        result = self.run_capture(custom=custom)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("999999", self.log.read_text())
        self.assertTrue(self.output.read_bytes().startswith(b"\x0a"))
        self.assert_clean()

    def test_legacy_perfetto_failure_and_empty_trace_are_rejected(self):
        self.env["FAKE_LEGACY"] = "1"
        for mode in ("early-fail", "fail", "empty"):
            with self.subTest(mode=mode):
                self.env["FAKE_MODE"] = mode
                result = self.run_capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assert_failed_cleanup(result.stderr)

    def test_ring_waits_for_signal_and_saves(self):
        self.assert_ring_capture()

    def test_legacy_ring_waits_for_signal_and_saves(self):
        self.env["FAKE_LEGACY"] = "1"
        self.assert_ring_capture()

    def test_perfetto_errors_and_empty_output_are_not_success(self):
        for mode in ("fail", "early-fail", "empty"):
            with self.subTest(mode=mode):
                self.env["FAKE_MODE"] = mode
                result = self.run_capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assert_failed_cleanup(result.stderr)

    def test_existing_output_and_temporary_files_are_preserved(self):
        for suffix in ("", ".system.tmp", ".config.tmp"):
            with self.subTest(suffix=suffix):
                existing = Path(str(self.output) + suffix)
                existing.write_bytes(b"keep")
                result = self.run_capture()
                if "PERFETTO_TEST_ROOT" in self.env and suffix:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.output.unlink()
                else:
                    self.assertNotEqual(result.returncode, 0)
                self.assertEqual(existing.read_bytes(), b"keep")
                existing.unlink()
                self.assert_clean()


class AndroidSystemOnlyCaptureTest(SystemOnlyCaptureTest):
    def setUp(self):
        super().setUp()
        self.driver = self.android_driver
        self.combined_driver = self.android_driver
        self.env["PERFETTO_TEST_ROOT"] = str(self.perfetto_root)

    def assert_clean(self):
        super().assert_clean()
        for directory in ("configs", "traces"):
            self.assertEqual(list((self.perfetto_root / directory).iterdir()), [])


@unittest.skipUnless(os.environ.get("ANETTRACE_TEST_BIN"), "full CLI binary not supplied")
class SystemOnlyCliTest(CaptureTestCase):
    # The native and Android drivers cover the full capture state machine.
    # Keep CLI coverage focused on argument wiring and observable outcomes.
    test_duration_and_no_network = SystemOnlyCaptureTest.test_duration_and_no_network
    test_waits_for_delayed_binary_ready_ack = SystemOnlyCaptureTest.test_waits_for_delayed_binary_ready_ack
    test_legacy_perfetto_without_notify_fd_captures = SystemOnlyCaptureTest.test_legacy_perfetto_without_notify_fd_captures
    test_ring_waits_for_signal_and_saves = SystemOnlyCaptureTest.test_ring_waits_for_signal_and_saves
    test_bad_ack_is_rejected_and_child_is_reaped = SystemOnlyCaptureTest.test_bad_ack_is_rejected_and_child_is_reaped
    test_perfetto_errors_and_empty_output_are_not_success = SystemOnlyCaptureTest.test_perfetto_errors_and_empty_output_are_not_success
    test_existing_output_and_temporary_files_are_preserved = SystemOnlyCaptureTest.test_existing_output_and_temporary_files_are_preserved

    @classmethod
    def setUpClass(cls):
        """Use the supplied CLI binary without compiling unused test drivers."""

    def command(self, ring=False, custom="", duration=1):
        cmd = [os.environ["ANETTRACE_TEST_BIN"], "--capture-trace",
               "--system-trace-only", "--duration", str(duration),
               "--output", str(self.output)]
        if ring:
            cmd.append("--ring-buffer")
        if custom:
            cmd += ["--perfetto-config", str(custom)]
        else:
            cmd += ["--trace-profile", "sched"]
        return cmd

    def test_network_options_rejected(self):
        self.assertNotEqual(os.geteuid(), 0, "CLI regression must run without root")
        for flags in (["--traffic"], ["--uid", "10000"], ["--trace-detail"],
                      ["--connect-diagnostics"], ["--dport", "443"]):
            result = subprocess.run(self.command() + flags, env=self.env,
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"--system-trace-only cannot be combined", result.stderr)
        result = subprocess.run([os.environ["ANETTRACE_TEST_BIN"], "--system-trace-only"],
                                capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--system-trace-only requires --capture-trace", result.stderr)


if __name__ == "__main__":
    unittest.main()
