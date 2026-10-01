#!/usr/bin/env python3
"""Root/BTF regression: both capture modes preserve socket/packet/call chains."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def exercise(binary, protocol, group=False, detailed=False):
    with tempfile.TemporaryDirectory() as tmp:
        events = Path(tmp) / 'events.jsonl'
        log = Path(tmp) / 'capture.log'
        command = [str(binary), '--perfetto-events', str(events),
                   '--pid', str(os.getpid()), '--proto', protocol]
        if group:
            command += ['--trace', protocol]
        if detailed:
            command += ['--trace-detail']
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
                            for _ in range(3):
                                client.sendall(b'request')
                                assert peer.recv(7, socket.MSG_WAITALL) == b'request'
                                peer.sendall(b'response')
                                assert client.recv(8, socket.MSG_WAITALL) == b'response'
                    else:
                        for _ in range(3):
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
            stages = ({'send': ('__tcp_transmit_skb',),
                       'receive': ('tcp_v4_rcv',)} if protocol == 'tcp' else
                      {'send': ('ip_output',), 'receive': ('udp_rcv',)})
            expected = stages[direction] if detailed else (f'{protocol.upper()} packet {direction}',)
            matching = [r for r in packets if r['stage'] in expected]
            assert matching, (protocol, group, direction, packets, log.read_text())
            assert any(r['flow_anchor'] and r['flow_id'] for r in matching), matching
        calls = {r['call_id']: r for r in records if r['type'] == 'network_syscall'}
        io_ids = {r['io_id'] for r in records
                  if r['type'] in ('tx_write_start', 'rx_read_start')}
        packet_ids = {r['packet_id'] for r in packets}
        links = [r for r in records if r['type'] == 'packet_io_link'
                 and r['packet_id'] in packet_ids]
        for direction in ('tx', 'rx'):
            linked_calls = {r['call_id'] for r in links
                            if r['direction'] == direction and r['io_id'] in io_ids
                            and r['call_id'] in calls and calls[r['call_id']]['result'] > 0}
            assert len(linked_calls) >= 3, (protocol, detailed, direction, links, calls)
        created = {r['socket_id'] for r in records if r['type'] == 'socket_create'}
        bridges = [r for r in records if r['type'] == 'socket_flow_link'
                   and r['socket_id'] in created]
        assert any(c.get('socket_id') == b['socket_id'] and c.get('flow_id') == b['flow_id']
                   for b in bridges for c in calls.values()), (bridges, calls)
        if detailed:
            assert any(r['stage'] == 'ip_rcv' for r in packets), packets
        else:
            assert not any(r['stage'] == 'ip_rcv' for r in packets), packets
        print(f'{protocol} group={group} detailed={detailed}: '
              'socket creation, flow, repeated TX/RX and application calls PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    for protocol in ('tcp', 'udp'):
        for group in (False, True):
            exercise(args.binary.resolve(), protocol, group)
        exercise(args.binary.resolve(), protocol, detailed=True)
