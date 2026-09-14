#!/usr/bin/env python3
"""CI-only root/BTF workload: ordinary UDP packets and actual application I/O."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def exercise(binary):
    with tempfile.TemporaryDirectory() as tmp:
        events = Path(tmp) / 'events.jsonl'
        log = Path(tmp) / 'capture.log'
        with log.open('w') as output:
            tracer = subprocess.Popen([str(binary), '--libbpf-debug', '--perfetto-events', str(events),
                                       '--pid', str(os.getpid())],
                                      stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 180
                while 'begin trace...' not in log.read_text():
                    if tracer.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(log.read_text())
                    time.sleep(0.1)
                time.sleep(0.2)  # readiness is set immediately after the banner
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    server.bind(('127.0.0.1', 0))
                    server.settimeout(3)
                    client.settimeout(3)
                    target = server.getsockname()
                    assert target[1] != 53
                    # Unconnected UDP must form a flow from packet endpoints.
                    client.sendto(b'game-request', target)
                    data, peer = server.recvfrom(1024)
                    assert data == b'game-request'
                    server.sendto(b'game-response', peer)
                    assert client.recvfrom(1024)[0] == b'game-response'
                    # Connected sockets also expose file-style read/write APIs.
                    client.connect(target)
                    client.settimeout(None)
                    os.write(client.fileno(), b'write')
                    assert server.recvfrom(1024)[0] == b'write'
                    server.sendto(b'read', peer)
                    assert os.read(client.fileno(), 1024) == b'read'
                    os.writev(client.fileno(), [b'write', b'v'])
                    assert server.recvfrom(1024)[0] == b'writev'
                    server.sendto(b'readv', peer)
                    buf = bytearray(32)
                    assert os.readv(client.fileno(), [buf]) == 5
                    # A regular file read must not appear in Network syscalls.
                    with open('/dev/null', 'rb') as unrelated:
                        unrelated_fd = unrelated.fileno()
                        os.read(unrelated_fd, 32)
                time.sleep(0.3)
            finally:
                if tracer.poll() is None:
                    tracer.send_signal(signal.SIGINT)
                try:
                    tracer.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    tracer.kill()
                    tracer.wait()
        assert tracer.returncode == 0, log.read_text()
        records = [json.loads(line) for line in events.read_text().splitlines()]
        packets = [r for r in records if r['type'] == 'packet_event'
                   and r.get('proto_l4') == 17 and 53 not in (r.get('sport'), r.get('dport'))]
        assert packets, log.read_text()
        assert any(r.get('stage') == 'UDP packet send' for r in packets)
        flows = [r for r in records if r['type'] == 'flow_start' and r['protocol'] == 'udp']
        assert flows, records
        calls = [r for r in records if r['type'] == 'network_syscall']
        assert {'sendto', 'recvfrom', 'read', 'write', 'readv', 'writev'} <= {r['syscall'] for r in calls}
        assert not any(r['syscall'] == 'read' and r['fd'] == unrelated_fd for r in calls)
        links = [r for r in records if r['type'] == 'packet_io_link']
        assert any(r['evidence'] == 'submission_context' for r in links), records
        assert any(r['evidence'] == 'copy_attempt' for r in links), records
        assert any(r['type'] == 'flow_end' and r['end_reason'] == 'socket_destroy' for r in records)
        packet_ids = {r['packet_id'] for r in packets}
        assert len(packet_ids) > 1
        assert all(r['packet_id'] in packet_ids for r in links)
        io_ids = {r['io_id'] for r in records if r['type'] in ('tx_write_start', 'rx_read_start')}
        call_ids = {r['call_id'] for r in calls}
        assert all(r['io_id'] in io_ids for r in links), records
        assert all(r['call_id'] in call_ids for r in links), records
        assert any(len({r['stage'] for r in packets if r['packet_id'] == pid}) > 1
                   for pid in packet_ids), records
        print(f'UDP trace: {len(packets)} stages, {len(packet_ids)} skb instances, '
              f'{len(flows)} flows, {len(calls)} syscalls, {len(links)} I/O links')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    exercise(parser.parse_args().binary.resolve())
