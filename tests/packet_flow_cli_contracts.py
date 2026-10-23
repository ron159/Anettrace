#!/usr/bin/env python3
"""Check packet-flow options before privileged kernel setup."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = str(parser.parse_args().binary.resolve())
    result = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    for option in ("--tid", "--pid", "--wakeup-chain", "--rx-context"):
        assert option in result.stdout, option
    cases = [
        (["--tid", "12", "--pid", "12"], "--pid and --tid are aliases"),
        (["--wakeup-chain"], "--wakeup-chain requires --capture-trace or --perfetto-events"),
        (["--rx-context"], "--rx-context requires --capture-trace or --perfetto-events"),
        (["--rx-context", "--perfetto-events", "/tmp/unused.jsonl", "--force"],
         "--rx-context requires --uid without --tid/--pid"),
        (["--rx-context", "--perfetto-events", "/tmp/unused.jsonl", "--tid", "12"],
         "--rx-context requires --uid without --tid/--pid"),
        (["--rx-context", "--perfetto-events", "/tmp/unused.jsonl", "--uid", "10000", "--pid", "12"],
         "--rx-context requires --uid without --tid/--pid"),
        (["--rx-context", "--perfetto-events", "/tmp/unused.jsonl", "--uid", "10000", "--tid", "0"],
         "--rx-context requires --uid without --tid/--pid"),
        (["--capture-trace", "--rx-context", "--uid", "10000", "--trace-profile", "invalid"],
         "--trace-profile must be full or sched"),
        (["--capture-trace", "--system-trace-only", "--rx-context"],
         "--system-trace-only cannot be combined with --rx-context"),
        (["--capture-trace", "--system-trace-only", "--wakeup-chain"],
         "--system-trace-only cannot be combined with --wakeup-chain"),
        (["--capture-trace", "--system-trace-only", "--tid", "12"],
         "--system-trace-only cannot be combined with --tid"),
        # An accepted alias reaches the next independent argument validation.
        (["--capture-trace", "--tid", "12", "--trace-profile", "invalid"],
         "--trace-profile must be full or sched"),
    ]
    for options, expected in cases:
        result = subprocess.run([binary, *options], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0, options
        assert expected in result.stdout + result.stderr, (options, result.stdout, result.stderr)
    print("packet-flow CLI: thread alias, optional wake context, mode conflicts PASS")


if __name__ == "__main__":
    main()
