# 抓取缓冲区与事件丢失

`lost_events` 表示采集记录丢失，不能据此判断网络丢包。BPF 在各 CPU 的
perf 环形缓冲区中写入事件，用户态消费不足时缓冲区会满。

## 扩大缓冲区的代价

perf 数据区内存约为 `CPU 缓冲区数量 × 页数 × 系统页大小`，每个 CPU 另有一页元数据。
这些页在抓取期间占用内核内存；增加容量主要增加内存和可容纳的积压，不降低每个事件的处理成本。
高负载下还会延长退出前的排空时间。CPU 数量、内核页大小和可用锁页额度会影响分配能否成功。

以 8 个 CPU、4 KiB 页为例：

| 页数/CPU | 每 CPU 数据区 | 数据区合计 | 比原先增加 |
| --- | --- | --- | --- |
| 1024（原值） | 4 MiB | 32 MiB | 0 |
| 4096 | 16 MiB | 128 MiB | 96 MiB |
| 8192 | 32 MiB | 256 MiB | 224 MiB |

假设每条 perf 记录共 224 字节，单 CPU 分别能容纳约 1.87 万、7.49 万、14.98 万条。
这是容量估算，实际记录大小取决于事件类型。CPU 的容量彼此独立，空闲 CPU 的空间不能供繁忙 CPU 使用。
当事件产生速率持续超过处理速率时，任何有限容量最终都会溢出。

## 当前采集策略

- Perfetto 输出默认分配 **16 MiB/CPU**，根据实际页大小换算页数，避免 16/64 KiB 页设备额外放大内存。
- `--capture-trace` 使用 **32 MiB 固定有界队列**。采集线程只复制原始事件，工作线程负责关联、编码和写盘。
  8 CPU 设备上，perf 数据区加导出队列约 **160 MiB**，比旧版增加约 **128 MiB**；另有 BPF map、
  导出状态、线程栈、系统 Perfetto 等内存。
- 队列满时采集线程不等待磁盘，准确记录队列丢失；`trace_end.lost_events` 包含内核与队列丢失。
  原生轨迹的 `capture_queue.lost_events` 单独记录队列丢失，JSONL 的 `trace_end.queue_lost_events` 同义。
- 抓取结束时先关闭 BPF 生产开关，消费残留 perf 数据，再排空已接收的队列；收到 SIGINT 也会排空。
  所以命令退出可能晚于 `--duration`，排空时间不代表延长有效抓取。
- 原生抓取不再逐条打印丢失警告，结束时汇总。普通终端跟踪保留原来的 1024 页/CPU 和丢失时停止行为。
  `--perfetto-events` 的终端分析仍同步执行。

可覆盖页数，必须为 64 到 16384 之间的 2 的幂：

```sh
# 内存受限设备：4 KiB 页时恢复为 4 MiB/CPU，仍使用异步导出队列
anettrace --capture-trace --uid 10187 --duration 10 \
  --perf-buffer-pages 1024 --output capture.pftrace
```

优先缩小 UID、协议、端口范围；扩大 perf 缓冲区适合吸收突发。
持续过载需要减少事件量或降低导出成本，不能承诺所有负载下零丢失。

参考：[Linux perf ring buffer](https://docs.kernel.org/userspace-api/perf_ring_buffer.html)。
