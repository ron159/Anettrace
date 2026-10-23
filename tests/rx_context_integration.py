#!/usr/bin/env python3
"""Root/Linux regression: confirm early RX by skb identity without leaking peers."""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time

TARGET_UID = 12345
OTHER_UID = 12346
PACKETS = 32
EARLY_RX_STAGES = {"ip_rcv", "ip_rcv_core", "ip_rcv_finish", "ip_local_deliver"}

# The child starts before capture, but creates its socket only after the tracer
# is ready. Dropping credentials before socket() makes sk_uid authoritative.
RECEIVER = r'''
import json, os, socket, sys
uid, count = int(sys.argv[1]), int(sys.argv[2])
if os.geteuid() == 0:
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
assert os.getuid() == uid
print(json.dumps({"uid": os.getuid(), "pid": os.getpid()}), flush=True)
assert sys.stdin.readline() == "bind\n"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(10)
    print(json.dumps({"port": receiver.getsockname()[1]}), flush=True)
    for sequence in range(count):
        data, peer = receiver.recvfrom(128)
        assert data == ("rx-context-%d" % sequence).encode(), (sequence, data)
        print(json.dumps({"received": sequence, "peer_port": peer[1]}), flush=True)
'''


def read_json(process, timeout=15):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise AssertionError("receiver did not acknowledge the workload step")
    line = process.stdout.readline()
    if not line:
        raise AssertionError(f"receiver exited before acknowledgement: {process.stderr.read()}")
    return json.loads(line)


def start_receiver(uid):
    process = subprocess.Popen([sys.executable, "-c", RECEIVER, str(uid), str(PACKETS)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        identity = read_json(process)
        assert identity["uid"] == uid, identity
        return process
    except BaseException:
        process.kill()
        process.wait()
        raise


def bind_receiver(process):
    process.stdin.write("bind\n")
    process.stdin.flush()
    return read_json(process)["port"]


def send_and_confirm(sender, receiver, port, sequence):
    payload = f"rx-context-{sequence}".encode()
    assert sender.sendto(payload, ("127.0.0.1", port)) == len(payload)
    ack = read_json(receiver)
    assert ack == {"received": sequence, "peer_port": sender.getsockname()[1]}, ack


def stop_process(process):
    if process and process.poll() is None:
        process.kill()
        process.wait(timeout=10)


def workload_self_test():
    """Validate pipe synchronization and UDP delivery without requiring BPF."""
    receiver = start_receiver(os.geteuid())
    try:
        port = bind_receiver(receiver)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind(("127.0.0.1", 0))
            for sequence in range(PACKETS):
                send_and_confirm(sender, receiver, port, sequence)
        assert receiver.wait(timeout=10) == 0, receiver.stderr.read()
        print(f"RX receiver workload: {PACKETS}/{PACKETS} packets PASS")
    finally:
        stop_process(receiver)


def exercise(binary, enabled):
    receiver = other_receiver = tracer = None
    with tempfile.TemporaryDirectory() as tmp:
        events, log = Path(tmp) / "events.jsonl", Path(tmp) / "capture.log"
        try:
            receiver = start_receiver(TARGET_UID)
            other_receiver = start_receiver(OTHER_UID)
            command = [str(binary), "--perfetto-events", str(events), "--trace-detail",
                       "--uid", str(TARGET_UID), "--proto", "udp"]
            if enabled:
                command += ["--rx-context"]
            with log.open("w") as output:
                tracer = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 120
                while "begin trace..." not in log.read_text():
                    if tracer.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(log.read_text())
                    time.sleep(0.05)
                target_port, other_port = bind_receiver(receiver), bind_receiver(other_receiver)
                assert target_port != other_port
                # Root executes both sends. Only one receiving socket belongs
                # to the selected UID; neither tuple is known before capture.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, \
                        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other_sender:
                    sender.bind(("127.0.0.1", 0))
                    other_sender.bind(("127.0.0.1", 0))
                    target_sender_port = sender.getsockname()[1]
                    other_sender_port = other_sender.getsockname()[1]
                    for sequence in range(PACKETS):
                        send_and_confirm(sender, receiver, target_port, sequence)
                        send_and_confirm(other_sender, other_receiver, other_port, sequence)
                    assert receiver.wait(timeout=10) == 0, receiver.stderr.read()
                    assert other_receiver.wait(timeout=10) == 0, other_receiver.stderr.read()
                    time.sleep(0.3)
                    tracer.send_signal(signal.SIGINT)
                    tracer.wait(timeout=15)
            assert tracer.returncode == 0, log.read_text()
            records = [json.loads(line) for line in events.read_text().splitlines()]
            packets = [record for record in records if record.get("type") == "packet_event"]
            target_packets = [record for record in packets
                              if record.get("sport") == target_sender_port
                              and record.get("dport") == target_port]
            assert target_packets, log.read_text()
            unrelated_ports = {other_sender_port, other_port}
            assert not any(record.get(field) in unrelated_ports for record in records
                           for field in ("sport", "dport", "local_port", "remote_port")), records
            assert not any(record.get("owner_uid") == OTHER_UID for record in records), records
            if not enabled:
                assert all("owner_evidence" not in record for record in records), records
                assert not any(record.get("type") == "rx_context" for record in records), records
            else:
                recovered = [record for record in target_packets
                             if record.get("owner_evidence") == "same_skb_instance"
                             and record.get("stage") in EARLY_RX_STAGES]
                assert recovered, (target_packets, log.read_text())
                assert all(record.get("owner_uid") == TARGET_UID
                           and record.get("owner_valid") for record in recovered), recovered
                assert any(record.get("uid") == 0 for record in recovered), recovered
                proofs = [record for record in target_packets
                          if record.get("owner_evidence") == "direct_socket"
                          and record.get("owner_uid") == TARGET_UID]
                for record in recovered:
                    assert any(proof["packet_id"] == record["packet_id"]
                               and proof["owner_socket_id"] == record["owner_socket_id"]
                               and proof["ts_ns"] >= record["ts_ns"] for proof in proofs), record
                summary = [record for record in records if record.get("type") == "rx_context"]
                assert len(summary) == 1, summary
                assert summary[0]["replayed_events"] >= len(recovered), summary
                # The unrelated receiver generated early metadata, but none
                # acquired target-socket proof and therefore none was exported.
                assert summary[0]["unresolved_events"] + summary[0]["expired_events"] > 0, summary
                print(f"RX context: {len(recovered)} early stages confirmed by direct skb evidence")
            print(f"rx-context enabled={enabled}: target traffic retained, other UID absent PASS")
        finally:
            for process in (tracer, receiver, other_receiver):
                stop_process(process)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path)
    parser.add_argument("--workload-self-test", action="store_true")
    args = parser.parse_args()
    if args.workload_self_test:
        workload_self_test()
    else:
        if args.binary is None:
            parser.error("specify the Anettrace binary")
        if sys.platform != "linux" or os.geteuid() != 0:
            raise SystemExit("This integration test requires Linux root and kernel BTF.")
        for enabled in (False, True):
            exercise(args.binary.resolve(), enabled)
