# 应用收发链路采集

这组能力补齐采集范围、直接唤醒证据、早期 RX 归属和事件状态，方便在 Perfetto
中检查应用的收发过程。它不生成自动根因结论或收发性能报告。

## 按应用抓取

在主机上准备对应版本的 Android binary，然后运行：

```sh
python3 tools/capture_android_trace.py \
  --package com.example.app --anettrace ./anettrace \
  --wakeup-chain --rx-context --trace-detail \
  --duration 15 --out output/app-flow
```

需要已具备 root 权限的设备 shell；如果使用可信的提权方式，可显式传入
`--root-command 'su -c'`。工具不会自行尝试提权。`--package` 仅是主机工具参数，
它通过 Android package manager 精确解析 UID。共享 UID 会提示范围包含多个包；
UID 过滤不能将共享 UID 的应用彼此分离。找不到包或解析结果不唯一时终止采集。

`--tid 1234` 只筛选线程 1234，不包含进程的其他线程。旧 `--pid` 保持同样语义；
两者不可同时使用。`--package` 与 `--uid` 互斥。普通采集可附加 `--tid` 缩小范围，
本版 `--rx-context` 则仅支持应用 UID 范围，不能与 `--tid`/`--pid` 组合。
包名模式默认不在 manifest 中保存包名和设备标识，但网络轨迹仍包含 IP、端口和
线程名称等诊断数据。

设备端也可直接抓取：

```sh
./anettrace --capture-trace --uid 10187 \
  --wakeup-chain --rx-context --trace-detail --duration 15 \
  --output /data/local/tmp/app-flow.pftrace
```

等待采集就绪提示后再复现。网络端会先创建 perf buffer，再开启 BPF 输出；系统端
先探测 Perfetto 的 `--help`。支持 `--notify-fd` 时等待数据源启动确认；确认失败、
提前退出或超时仍会报错。旧版不支持时使用前台兼容采集，提示无法确认数据源启动，
采集时长从进程启动后计算；该模式的启动提示只表示进程存活。主机工具也会探测该能力，
旧版模式在 manifest 中将 Perfetto 标记为 `started_unconfirmed`。主机 manifest 记录各采集端的
就绪状态和整体就绪时间。数据源确认不代表设备支持配置中的每一个可选内核探针。

## 查看直接唤醒证据

`--wakeup-chain` 默认关闭，开启后要求 `sched_waking`、`sched_wakeup`、
`sched_switch` 和网络 syscall 入口/出口可用；缺少必需探针会明确报错。
不需要额外开启 `--trace-detail`。

打开 `.pftrace`，在目标线程的 `Network syscalls` 轨道选中 send/recv/read/write
等调用，查看以下参数：

| 参数 | 含义 |
| --- | --- |
| `wakeup_status=observed` | 当前连续运行区间之前观察到了 waking、成功 wakeup 和首次运行 |
| `waking_ts_ns` | 发起唤醒的观测时间 |
| `wakeup_ts_ns` | 线程成功成为可运行状态的观测时间 |
| `run_start_ts_ns` | 该连续运行区间的开始时间 |
| `waking_cpu` / `run_cpu` | 唤醒来源与首次运行 CPU |
| `waking_context` | `task`、`hardirq`、`softirq`、`nmi` 或 `unknown` |
| `waking_preempt_count` | 判断上下文时读取的原始内核计数；无法可靠读取时不输出 |
| `waker_tid` / `waker_tgid` / `waker_task` | 仅任务上下文中的直接唤醒线程 |
| `waker_start_time_ns` | 唤醒线程的创建时间标识，用于区别 TID 复用 |

时间戳与网络事件使用单调时钟。可用 `run_start_ts_ns - wakeup_ts_ns` 检查这次
唤醒后的调度等待，并回到系统调度轨道核对。

`unknown` 表示尚无足够证据；`run_without_observed_wake` 表示记录到运行开始，
但没有对应的成功唤醒证据，例如抢占后重新运行。中断上下文不输出伪造的 waker
线程。首次看到的线程、身份变化和缓存淘汰都允许保留未知。
若内核不提供可靠的上下文计数，时间顺序仍可记录，`waking_context` 保留为
`unknown`，不输出唤醒线程身份。不会把中断期间恰好运行的线程当成唤醒者。
当前上下文位布局按 Linux 6.x 及更早版本处理；Linux 7.0 及更新版本保留为未知，
待适配对应布局后再启用身份归因。

关联的是**调用进入时所在的连续运行区间**。同一区间内多个调用可能带相同上下文；
调用阻塞之后的唤醒不会替换入口快照。这不证明唤醒者在业务上要求了这次发送，
也尚未包含 Binder、futex、epoll 的上游对象链或 `socket readable` 到 wakee 的直接边。
结合[现有链路字段与查询](perfetto-chain.md)继续查看 `call_id`、`io_id`、`packet_id`。

## 保留应用过滤前的 RX 阶段

`--rx-context` 默认关闭，要求 Perfetto 输出以及 UID 过滤（可由包名解析）。本版不接受
TID 过滤：socket 创建者和实际读取线程可能不同，现有 socket owner 不能证明读取者。
开启后，早期尚无
socket 归属的 RX 元数据会暂存在用户态待确认缓存中，不立即写入 JSONL 或 `.pftrace`。
只有后续同一个 skb 地址与分配代次获得匹配目标的直接 socket 证据，才补全并导出。

补全保留原始时间、CPU 和执行线程，owner 与执行者分别保存。不会将其他应用的已知
socket、仅五元组匹配或时间相近作为确认依据；不会把后续 I/O 的 `call_id` 反填给
早期未知事件。`owner_evidence` 区分直接 socket 证据和同 skb 实例补全。

缓存上限为 4096 个事件、8 MiB 和 1 秒；跨 CPU 乱序到达也必须满足时间窗口。
未解决的内容不会输出，`rx_context` 元数据记录回放、过期、容量丢弃和结束时仍未
解决的事件数。这些是采集完整性计数，不是网络丢包数。开启该选项会增加早期 RX
元数据进入 perf buffer 的数量，高流量环境应关注 `lost_events`。

需要 `--trace-detail` 才能看到已挂载的早期协议栈节点。GRO、GSO、clone 等导致 skb
实例变化时，目前仍不跨实例补全。没有获得 socket 证据的包也不会强行归属。

## 查看已经采到的状态

Socket 事件与状态变化补充 `state`、`wqlen`、`rqlen`；TCP 额外提供
`packets_out`、`retrans_out`、`snd_una`。`wqlen/rqlen` 是 skb 队列长度，
不是缓冲字节数；`snd_una` 是 TCP 序号。

详细模式的 qdisc 事件补充 `qdisc_qlen`、`netdev_queue_state`、`qdisc_flags`。
可读取时提供 `qdisc_last_update_jiffies`，表示距设备队列 `trans_start` 的 jiffies
差值，不是纳秒或线上发送时间；不可用时省略。原生导出与 JSONL 转换保留相同字段。

内核函数入口仍表示阶段观测或尝试，成功字节以系统调用返回为准。
`dev_hard_start_xmit` 入口也不代表数据已经到达网卡或空口。
