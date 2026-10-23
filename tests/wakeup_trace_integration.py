#!/usr/bin/env python3
"""Root/Linux BPF regression for direct task-context wake -> UDP send evidence."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def exercise(binary, workload, enabled):
    with tempfile.TemporaryDirectory() as tmp:
        events, log = Path(tmp) / "events.jsonl", Path(tmp) / "capture.log"
        worker = subprocess.Popen([str(workload)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        tracer = None
        try:
            identity = json.loads(worker.stdout.readline())
            command = [str(binary), "--perfetto-events", str(events),
                       "--pid", str(identity["sender_tid"]), "--proto", "udp"]
            if enabled:
                command += ["--wakeup-chain"]
            with log.open("w") as output:
                tracer = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 120
                while "begin trace..." not in log.read_text():
                    if tracer.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(log.read_text())
                    time.sleep(0.05)
                # Compatible with binaries whose ready flag follows the banner.
                time.sleep(0.2)
                stdout, stderr = worker.communicate("g\n", timeout=15)
                assert worker.returncode == 0, stderr
                assert json.loads(stdout)["packets"] == 32, stdout
                time.sleep(0.2)
                tracer.send_signal(signal.SIGINT)
                tracer.wait(timeout=15)
            assert tracer.returncode == 0, log.read_text()
            records = [json.loads(line) for line in events.read_text().splitlines()]
            calls = [r for r in records if r.get("type") == "network_syscall"
                     and r.get("tid") == identity["sender_tid"]
                     and r.get("syscall") == "sendto"
                     and r.get("fd") == identity["sender_fd"] and r.get("result") == 13]
            assert len(calls) >= 24, (len(calls), log.read_text())
            if not enabled:
                assert all("wakeup_status" not in call for call in calls), calls
            else:
                observed = [r for r in calls if r.get("wakeup_status") == "observed"
                            and r.get("waker_tid") == identity["waker_tid"]]
                assert observed, (calls, log.read_text())
                for call in observed:
                    assert call["waking_context"] == "task", call
                    count = call["waking_preempt_count"]
                    assert isinstance(count, int) and 0 <= count <= 0xffffffff, call
                    assert count & 0x00ff0100 == 0, call
                    assert "waking_flags" not in call, call
                    assert call["waker_tgid"] == identity["tgid"], call
                    assert call["waker_start_time_ns"] > 0, call
                    assert (0 < call["waking_ts_ns"] <= call["wakeup_ts_ns"]
                            <= call["run_start_ts_ns"] <= call["start_ts_ns"]), call
                # No fabricated predecessor is allowed on a newly seen task/run.
                for call in calls:
                    if call.get("wakeup_status") in ("unknown", "run_without_observed_wake"):
                        assert "waker_tid" not in call and "waking_ts_ns" not in call, call
            print(f"wakeup-chain enabled={enabled}: {len(calls)} real UDP sends PASS")
        finally:
            for process in (tracer, worker):
                if process and process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("This integration test requires root and kernel BTF.")
    with tempfile.TemporaryDirectory() as tmp:
        workload = Path(tmp) / "wakeup-workload"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
                        str(ROOT / "tests/wakeup_workload.c"), "-o", str(workload)], check=True)
        for enabled in (False, True):
            exercise(args.binary.resolve(), workload, enabled)
