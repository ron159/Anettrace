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
import os, signal, sys, time
assert sys.argv[1:] == ["--txt", "-c", "-", "-o", "-"]
config = sys.stdin.read()
with open(os.environ["CONFIG_LOG"], "w") as log:
    log.write(config)
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
    sys.stdout.buffer.write(b"\x0a" + varint(len(packet)) + packet)
    sys.stdout.buffer.flush()
def stop(*args):
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
if os.environ.get("FAKE_MODE") == "fail":
    emit()
    time.sleep(0.4)
    sys.exit(7)
if os.environ.get("FAKE_MODE") == "early-fail":
    sys.exit(7)
if os.environ.get("FAKE_MODE") == "empty":
    time.sleep(0.4)
    sys.exit(0)
while True:
    emit()
    time.sleep(0.05)
'''

DRIVER = r'''
#include <stdlib.h>
#include <signal.h>
#include "trace_capture.h"
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    if (trace_capture_start(argv[1], atoi(argv[2]), "sched",
                            argv[4][0] ? argv[4] : NULL,
                            atoi(argv[3]), true)) return 1;
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
        cmd = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
               "-DANETTRACE_ANDROID_TARGET", f"-I{base}", f"-I{ROOT / 'src'}"]
        if sys.platform == "darwin":
            cmd += ["-DCLOCK_BOOTTIME=CLOCK_MONOTONIC"]
        subprocess.run(cmd + [str(base / "driver.c"),
                       str(ROOT / "src/trace_capture.c"),
                       str(ROOT / "src/perfetto_config.c"),
                       str(ROOT / "src/perfetto_trim.c"),
                       "-o", str(cls.driver)], check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="anettrace-system-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        fake = self.base / "perfetto"
        fake.write_text(f"#!{sys.executable}\n" + FAKE_PERFETTO)
        fake.chmod(0o755)
        self.output = self.base / "system.pftrace"
        self.log = self.base / "config.log"
        self.env = dict(os.environ, PATH=f"{self.base}:{os.environ['PATH']}",
                        CONFIG_LOG=str(self.log))

    def command(self, ring=False, custom="", duration=1):
        return [str(self.driver), str(self.output), str(duration),
                str(int(ring)), str(custom)]

    def run_capture(self, **kwargs):
        return subprocess.run(self.command(**kwargs), env=self.env,
                              capture_output=True, timeout=10)

    def assert_clean(self):
        self.assertEqual(list(self.base.glob("*.tmp")), [])

    def test_duration_stdin_stdout_and_no_network(self):
        start = time.monotonic()
        result = self.run_capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - start, 1)
        self.assertIn("duration_ms: 2000", self.log.read_text())
        self.assertTrue(self.output.read_bytes().startswith(b"\x0a"))
        self.assertNotIn(b"anettrace", self.output.read_bytes())
        self.assert_clean()

    def test_custom_duration_is_overridden(self):
        custom = self.base / "custom.pbtxt"
        custom.write_text('duration_ms: 999999\nbuffers { size_kb: 1024 }\n')
        result = self.run_capture(custom=custom)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("999999", self.log.read_text())
        self.assertIn("duration_ms: 2000", self.log.read_text())
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
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(existing.read_bytes(), b"keep")
                existing.unlink()
                self.assert_clean()


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
