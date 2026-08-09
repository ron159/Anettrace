// SPDX-License-Identifier: MulanPSL-2.0

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class FlowWorkload {
    private static final int IO_TIMEOUT_MS = 5_000;

    private FlowWorkload() {}

    public static void main(String[] args) throws Exception {
        long delayMs = args.length > 0 ? Long.parseLong(args[0]) : 5_000L;
        String readyFile = args.length > 1 ? args[1] : null;
        String pid = new String(
                        Files.readAllBytes(Paths.get("/proc/self/stat")),
                        StandardCharsets.US_ASCII)
                .split(" ", 2)[0];
        System.out.printf("READY pid=%s java_thread=%s delay_ms=%d ready_file=%s%n",
                pid, Thread.currentThread().getName(), delayMs, readyFile);
        System.out.flush();
        waitForReadyFile(readyFile);
        Thread.sleep(delayMs);

        try (Socket tcp1 = openTcp("1.1.1.1");
                DatagramSocket dns1 = openDns();
                Socket tcp2 = openTcp("1.0.0.1");
                DatagramSocket dns2 = openDns()) {
            byte[] request = ("GET / HTTP/1.0\r\n"
                            + "Host: one.one.one.one\r\n"
                            + "Connection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] query1 = dnsQuery(0x1201, "example.com");
            byte[] query2 = dnsQuery(0x1202, "example.net");

            writeTcp("TCP1", tcp1, request);
            sendDns("DNS1", dns1, "1.1.1.1", query1);
            writeTcp("TCP2", tcp2, request);
            sendDns("DNS2", dns2, "8.8.8.8", query2);

            readTcp("TCP1", tcp1);
            receiveDns("DNS1", dns1);
            readTcp("TCP2", tcp2);
            receiveDns("DNS2", dns2);
        }

        System.out.println("IO_COMPLETE idle_wait_ms=7000");
        System.out.flush();
        Thread.sleep(7_000L);
        System.out.println("DONE");
    }

    private static void waitForReadyFile(String readyFile) throws Exception {
        if (readyFile == null) {
            return;
        }
        long deadlineNs = System.nanoTime() + 180_000_000_000L;
        while (!Files.exists(Paths.get(readyFile))) {
            if (System.nanoTime() >= deadlineNs) {
                throw new IllegalStateException("Timed out waiting for " + readyFile);
            }
            Thread.sleep(50L);
        }
        System.out.printf("CAPTURE_READY ready_file=%s%n", readyFile);
        System.out.flush();
    }

    private static Socket openTcp(String address) throws Exception {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(address, 80), IO_TIMEOUT_MS);
        socket.setSoTimeout(IO_TIMEOUT_MS);
        return socket;
    }

    private static DatagramSocket openDns() throws Exception {
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(IO_TIMEOUT_MS);
        return socket;
    }

    private static void writeTcp(String name, Socket socket, byte[] request)
            throws Exception {
        OutputStream output = socket.getOutputStream();
        output.write(request);
        output.flush();
        System.out.printf("%s_TX bytes=%d local=%s remote=%s%n", name,
                request.length, socket.getLocalSocketAddress(), socket.getRemoteSocketAddress());
    }

    private static void readTcp(String name, Socket socket) throws Exception {
        InputStream input = socket.getInputStream();
        byte[] buffer = new byte[2_048];
        int total = 0;
        int count;
        while ((count = input.read(buffer)) > 0) {
            total += count;
            if (total >= buffer.length) {
                break;
            }
        }
        System.out.printf("%s_RX bytes=%d%n", name, total);
    }

    private static void sendDns(
            String name, DatagramSocket socket, String address, byte[] query)
            throws Exception {
        DatagramPacket packet = new DatagramPacket(
                query, query.length, InetAddress.getByName(address), 53);
        socket.send(packet);
        System.out.printf("%s_TX bytes=%d local=%s remote=%s:%d%n", name,
                query.length, socket.getLocalSocketAddress(), address, 53);
    }

    private static void receiveDns(String name, DatagramSocket socket) throws Exception {
        byte[] response = new byte[2_048];
        DatagramPacket packet = new DatagramPacket(response, response.length);
        socket.receive(packet);
        System.out.printf("%s_RX bytes=%d remote=%s%n", name,
                packet.getLength(), packet.getSocketAddress());
    }

    private static byte[] dnsQuery(int transactionId, String name) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write((transactionId >>> 8) & 0xff);
        output.write(transactionId & 0xff);
        output.write(new byte[] {0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00});
        for (String label : name.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            output.write(bytes.length);
            output.write(bytes);
        }
        output.write(0);
        output.write(new byte[] {0x00, 0x01, 0x00, 0x01});
        return output.toByteArray();
    }
}
