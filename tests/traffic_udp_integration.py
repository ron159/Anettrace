#!/usr/bin/env python3
"""Exercise real UDP traffic probes on a root/BTF-enabled Linux host."""

import argparse
import contextlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading


def endpoint(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def exercise(binary):
    lines = []
    ready = threading.Event()
    process = subprocess.Popen(
        [str(binary), "--traffic", "--proto", "udp", "--interval", "1",
         "--pid", str(os.getpid())],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    def read_output():
        for line in process.stdout:
            lines.append(line)
            if "Traffic UDP (" in line:
                ready.set()

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    expected = {}
    try:
        if not ready.wait(20):
            raise AssertionError("UDP tracer did not become ready")
        with contextlib.ExitStack() as stack:
            def udp(family, bind=None):
                sock = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                sock.settimeout(3)
                if bind:
                    sock.bind((bind, 0))
                return sock

            def exchange(client, server, local_address, remote_address,
                         connected=False, peek=False, short=False):
                target = server.getsockname()
                if connected:
                    client.connect(target)
                    client.send(b"x" * 1024)
                else:
                    if client.family == socket.AF_INET6 and server.family == socket.AF_INET:
                        target = ("::ffff:" + target[0], target[1])
                    client.sendto(b"x" * 1024, target)
                request, peer = server.recvfrom(2048)
                assert request == b"x" * 1024
                server.sendto(b"y" * 1024, peer)
                rx_kb = 0.5 if short else 1.0
                if peek:
                    assert client.recv(2048, socket.MSG_PEEK) == b"y" * 1024
                    rx_kb += 1.0
                # recv(), unlike recvfrom(), does not request msg_name.
                assert client.recv(512 if short else 2048) == b"y" * (512 if short else 1024)
                key = (endpoint(local_address, client.getsockname()[1]),
                       endpoint(remote_address, server.getsockname()[1]))
                tx, rx = expected.get(key, (0, 0))
                expected[key] = (tx + 1.0, rx + rx_kb)
                client.setblocking(False)
                try:
                    client.recv(1)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError("expected EAGAIN on empty UDP socket")
                client.settimeout(3)

            first = udp(socket.AF_INET, "127.0.0.1")
            second = udp(socket.AF_INET, "127.0.0.2")
            client4 = udp(socket.AF_INET)  # Autobind wildcard socket on first send.
            exchange(client4, first, "127.0.0.1", "127.0.0.1")
            exchange(client4, second, "127.0.0.1", "127.0.0.2", peek=True)
            exchange(client4, first, "127.0.0.1", "127.0.0.1", short=True)
            connected4 = udp(socket.AF_INET)
            exchange(connected4, first, "127.0.0.1", "127.0.0.1", connected=True)
            # sendto can override even a connected UDP socket's default peer.
            # The socket still filters incoming packets by its connected peer.
            connected4.sendto(b"x" * 1024, second.getsockname())
            assert second.recv(2048) == b"x" * 1024
            expected[endpoint("127.0.0.1", connected4.getsockname()[1]),
                     endpoint("127.0.0.2", second.getsockname()[1])] = (1.0, 0)
            server6 = udp(socket.AF_INET6, "::1")
            other6 = udp(socket.AF_INET6, "::1")
            client6 = udp(socket.AF_INET6)
            exchange(client6, server6, "::1", "::1")
            exchange(client6, other6, "::1", "::1", peek=True)
            exchange(udp(socket.AF_INET6), server6, "::1", "::1", connected=True)
            mapped = udp(socket.AF_INET6)
            mapped.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            exchange(mapped, first, "127.0.0.1", "127.0.0.1")
            # Corked writes have no skb until the flush: preserve those bytes
            # under an explicit unknown endpoint instead of inventing an IP.
            corked = udp(socket.AF_INET)
            corked.sendto(b"x" * 1024, socket.MSG_MORE, first.getsockname())
            corked.sendto(b"z" * 512, first.getsockname())
            request, peer = first.recvfrom(2048)
            assert request == b"x" * 1024 + b"z" * 512
            first.sendto(b"y" * 1024, peer)
            assert corked.recv(2048) == b"y" * 1024
            expected[endpoint("127.0.0.1", corked.getsockname()[1]),
                     endpoint("127.0.0.1", first.getsockname()[1])] = (0.5, 1.0)
            expected["?", "?"] = (1.0, 0)
    finally:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        reader.join(timeout=5)
        output = "".join(lines)
        print(output, end="")
    assert process.returncode == 0, f"tracer exited {process.returncode}"
    observed = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 9 or fields[0] != str(os.getpid()) or fields[3] != "UDP":
            continue
        local, remote = fields[5:7]
        assert not local.startswith(("0.0.0.0:", "[::]:")), line
        assert not remote.startswith(("0.0.0.0:", "[::]:")), line
        tx, rx = map(float, fields[7:9])
        old_tx, old_rx = observed.get((local, remote), (0, 0))
        observed[local, remote] = (max(tx, old_tx), max(rx, old_rx))
    for key, counters in expected.items():
        assert observed.get(key) == counters, (key, counters, observed.get(key))
    assert "samples dropped" not in output, output
    assert "UDP samples have unknown endpoints (?)" in output, output
    print(f"UDP endpoint integration passed: {len(expected)} client flows")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    exercise(args.binary.resolve())
