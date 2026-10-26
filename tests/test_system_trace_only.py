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
assert len(args) == 7 and args[0] == "--notify-fd"
notify_fd = int(args[1])
assert args[2:4] == ["--txt", "-c"] and args[5] == "-o"
config = sys.stdin.read() if args[4] == "-" else open(args[4]).read()
# Simulate a ROM which permits Perfetto only in its labelled directories.
if "PERFETTO_TEST_ROOT" in os.environ:
    root = os.environ["PERFETTO_TEST_ROOT"]
    assert args[4].startswith(root + "/configs/")
    assert args[6].startswith(root + "/traces/")
    assert not os.path.exists(args[6]), "shell must not pre-create the trace"
trace = sys.stdout.buffer if args[6] == "-" else open(args[6], "wb")
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
    trace.write(b"\x0a" + varint(len(packet)) + packet)
    trace.flush()
def stop(*args):
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
if mode != "no-ack":
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
#include <errno.h>
#include <fcntl.h>
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
int main(int argc, char **argv) {
    int combined = getenv("COMBINED") != NULL;
    if (argc != 5) return 2;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    if (trace_capture_start(argv[1], atoi(argv[2]), "sched",
                            argv[4][0] ? argv[4] : NULL,
                            atoi(argv[3]), !combined)) return 1;
    if (combined) {
        FILE *network = fopen(trace_capture_network_path(), "wb");
        if (!network) return 3;
        fputs("network", network);
        fclose(network);
        sleep(atoi(argv[2]));
        trace_capture_stop();
        return trace_capture_finish() ? 1 : 0;
    }
    if (trace_capture_network_path() != NULL) return 3;
    return trace_capture_wait_system(&stopped) ? 1 : 0;
}
'''


class SystemOnlyCaptureTest(unittest.TestCase):
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
        self.env = dict(os.environ, PATH=f"{self.base}:{os.environ['PATH']}",
                        CONFIG_LOG=str(self.log), PID_LOG=str(self.pid_log))

    def command(self, ring=False, custom="", duration=1):
        return [str(self.driver), str(self.output), str(duration),
                str(int(ring)), str(custom)]

    def run_capture(self, **kwargs):
        return subprocess.run(self.command(**kwargs), env=self.env,
                              capture_output=True, timeout=10)

    def assert_clean(self):
        self.assertEqual(list(self.base.glob("*.tmp")), [])
        if self.pid_log.exists():
            with self.assertRaises(ProcessLookupError):
                os.kill(int(self.pid_log.read_text()), 0)

    def test_waits_for_delayed_binary_ready_ack(self):
        self.env["FAKE_MODE"] = "delayed-ready"
        start = time.monotonic()
        result = self.run_capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - start, 2.25)
        self.assert_clean()

    def test_bad_ack_is_rejected_and_child_is_reaped(self):
        for mode in ("bad-ack", "ascii-ack"):
            with self.subTest(mode=mode):
                self.env["FAKE_MODE"] = mode
                result = self.run_capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assert_clean()

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
            self.assert_clean()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def test_readiness_timeout_aborts_and_reaps_child(self):
        self.env["FAKE_MODE"] = "no-ack"
        start = time.monotonic()
        result = subprocess.run(self.command(), env=self.env,
                                capture_output=True, timeout=40)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - start, 30)
        self.assertLess(time.monotonic() - start, 35)
        self.assertFalse(self.output.exists())
        self.assert_clean()

    def test_combined_capture_uses_the_same_ready_ack(self):
        if os.environ.get("ANETTRACE_TEST_BIN") and isinstance(self, SystemOnlyCliTest):
            self.skipTest("combined driver test uses no BPF")
        self.env["COMBINED"] = "1"
        self.env["FAKE_MODE"] = "delayed-ready"
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

    def test_ring_waits_for_signal_and_saves(self):
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

    def test_perfetto_errors_and_empty_output_are_not_success(self):
        for mode in ("fail", "early-fail", "empty"):
            with self.subTest(mode=mode):
                self.env["FAKE_MODE"] = mode
                result = self.run_capture()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assert_clean()

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
class SystemOnlyCliTest(SystemOnlyCaptureTest):
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
