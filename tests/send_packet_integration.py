#!/usr/bin/env python3
"""Root/BTF regression: real TCP/UDP payloads must have send flow anchors."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def exercise(binary, protocol, group=False):
    with tempfile.TemporaryDirectory() as tmp:
        events = Path(tmp) / 'events.jsonl'
        log = Path(tmp) / 'capture.log'
        command = [str(binary), '--perfetto-events', str(events),
                   '--pid', str(os.getpid()), '--proto', protocol]
        if group:
            command += ['--trace', protocol]
        with log.open('w') as output:
            tracer = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                while 'begin trace...' not in log.read_text():
                    if tracer.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(log.read_text())
                    time.sleep(0.1)
                time.sleep(0.2)
                kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
                with socket.socket(socket.AF_INET, kind) as server, \
                     socket.socket(socket.AF_INET, kind) as client:
                    server.bind(('127.0.0.1', 0))
                    server.settimeout(3)
                    client.settimeout(3)
                    port = server.getsockname()[1]
                    if protocol == 'tcp':
                        server.listen(1)
                        client.connect(server.getsockname())
                        with server.accept()[0] as peer:
                            peer.settimeout(3)
                            client.sendall(b'request')
                            assert peer.recv(7, socket.MSG_WAITALL) == b'request'
                            peer.sendall(b'response')
                            assert client.recv(8, socket.MSG_WAITALL) == b'response'
                    else:
                        client.sendto(b'request', server.getsockname())
                        data, peer = server.recvfrom(32)
                        assert data == b'request'
                        server.sendto(b'response', peer)
                        assert client.recvfrom(32)[0] == b'response'
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
                   and port in (r.get('sport'), r.get('dport'))]
        for direction in ('send', 'receive'):
            matching = [r for r in packets if r['stage'] == f'{protocol.upper()} packet {direction}']
            assert matching, (protocol, group, direction, packets, log.read_text())
            assert any(r['flow_anchor'] and r['flow_id'] for r in matching), matching
        print(f'{protocol} group={group}: send/receive labels and flow anchors PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    for protocol in ('tcp', 'udp'):
        for group in (False, True):
            exercise(args.binary.resolve(), protocol, group)
