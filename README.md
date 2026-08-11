# Anettrace

Anettrace 是面向 Linux 与已 root Android 设备的 eBPF 网络诊断工具。它从内核中的
`sk_buff`、socket、网络函数和 tracepoint 采集事件，把单个报文的协议栈路径、丢包原因、
处理延迟以及线程流量整理为可直接阅读的终端输出。

`master` 是推荐分支，构建产物名为 `anettrace`。当前版本同时保留 KPROBE/KRETPROBE
兼容后端与 BPF TRACING 后端，并提供 Android arm64 静态打包流程。

## 主要功能

- **报文生命周期追踪**：展示报文进入、经过和离开内核协议栈的函数路径，支持 IPv4、
  IPv6、TCP、UDP、ICMP、ARP 等协议。
- **组合过滤**：可按源/目标地址、端口、协议、网络命名空间、TID 和 UID 缩小范围；
  `--uid 0` 可正确过滤 root 流量。
- **故障诊断与丢包定位**：`--diag` 将事件与 `src/trace.yaml` 中的规则匹配，
  `--drop` 监控释放点并在内核支持时输出 skb drop reason。
- **性能分析**：支持协议栈延迟、延迟分布、TCP RTT、socket 生命周期与轻量监控模式。
- **Android 诊断字段**：可输出 TID、TGID、UID、CPU、网卡、IPv4 ID、skb mark、
  本地时间或原始单调时间戳。
- **线程流量视图**：`--traffic` 按 PID/TID、协议和本地/远端端点累计 TCP/UDP
  应用层收发字节。
- **Perfetto 联合时间线**：记录 socket 创建/状态、TCP 双向与 UDP DNS/53 双向路径、应用
  `recvmsg` 耗时/字节数，并与 Perfetto 线程调度状态合并；不保存报文 payload。

常用示例：

```shell
# 跟踪 ICMP 报文的内核路径
sudo ./src/anettrace --proto icmp --detail

# 诊断指定地址的异常报文
sudo ./src/anettrace --diag --addr 192.0.2.10

# 监控丢包并显示内核栈
sudo ./src/anettrace --drop --drop-stack

# 每 2 秒输出指定 UID 的 TCP 线程流量
sudo ./src/anettrace --traffic --proto tcp --uid 1000 --interval 2

# 查看当前内核实际可用的追踪目标
sudo ./src/anettrace -t "?"

# 仅导出指定 UID 的 socket/发包元数据，供 Perfetto 转换
sudo ./src/anettrace --uid 10000 \
  --perfetto-events /data/local/tmp/anettrace-events.jsonl
```

完整参数以 `./src/anettrace --help` 为准。

## 原理与架构

```text
命令行参数与过滤条件
        |
        v
trace.yaml --gen_trace.py--> 跟踪点、分组和诊断规则
        |
        v
用户态控制层（trace / analysis / traffic）
        |
        +--> KPROBE/KRETPROBE：默认、basic、diag、drop、sock、latency、traffic
        |
        +--> fentry/fexit：支持 trampoline 时的 monitor
        |
        +--> tracepoint/tp_btf：内核事件与 drop/reset reason
        |
        v
eBPF 过滤、上下文关联与 BPF maps
        |
        v
perf event / map 快照 -> 用户态聚合、规则匹配、格式化输出
```

核心流程分为四层：

1. **配置层**：`src/anettrace.c` 解析运行模式和过滤条件；
   `src/trace.yaml` 描述跟踪分组、函数、tracepoint 与诊断规则，
   `src/gen_trace.py` 在构建时生成 C 定义。
2. **挂载层**：主分支优先按模式选择后端。普通追踪通过 KPROBE/KRETPROBE
   适配更多内核；`--monitor` 在能力满足时使用 fentry/fexit；tracepoint
   继续按内核能力使用 tracepoint 或 tp_btf。
3. **内核采集层**：`src/progs/` 中的 eBPF 程序尽早执行地址、端口、协议、
   TID/UID 等过滤，并用 maps 保存报文上下文、调用栈和流量统计。
4. **用户态分析层**：`src/trace.c` 负责加载、挂载和轮询事件，
   `src/analysis.c` 关联报文生命周期并执行规则，
   `src/output.c` 与 `src/traffic.c` 生成最终输出。

`anettrace --help` 按使用目的分为六组：包与 owner 过滤、分析模式、Trace 采集与导出、事件显示、
高级 trace 控制、诊断与通用选项。建议先选择一种运行模式，再叠加过滤条件和该模式的输出选项。

`--traffic` 是独立统计通路：它在 TCP/UDP send/recv 的入口保存调用上下文，
在返回点按真实返回值累计字节，因此 `APP_TX_KB/APP_RX_KB` 显示的是可归属到线程的应用
payload，不包含协议头、SYN/ACK/FIN、重传、纯内核转发，以及尚未被应用读取的数据。收到
Ctrl-C 时会先打印最后一个未满统计区间。联合采集不需要也不会启动这套独立 skeleton；
`--capture-trace` 自身会在 `tcp/udp/udpv6 sendmsg/recvmsg` 返回点统计实际字节，并写入对应的
五元组 flow。两个模式不能在同一个进程组合，但可以分别启动两个 Anettrace 进程独立使用。

### Perfetto 联合时间线

`--perfetto-events FILE` 和 `--capture-trace` 默认使用精简网络模式，只采集关键工作点：

- `sk_alloc` 的 socket 分配开始/结束；
- TCP 状态变化、socket close、应用 write/read；
- TCP SYN/SYN-ACK/RST/FIN、普通 packet send/receive；
- DNS query/response send/receive；
- 每个事件的单调时钟时间、TID/TGID/UID、CPU、网卡和协议元数据。

需要查看原来的 TCP/IP、qdisc、NIC、skb clone/free 等完整内核函数链时追加
`--trace-detail`。该开关只控制 Anettrace 网络事件粒度，不改变系统 Perfetto 的
`full`/`sched` profile。
为维持 skb/owner 关联而自动附加的 clone/free 依赖探针在精简模式中不会打印或导出。

导出器每 5 秒以及结束时记录一次 `MONOTONIC/BOOTTIME/REALTIME` 时钟快照；转换后的网络
事件保留 `CLOCK_MONOTONIC` 时钟域，由 Trace Processor 使用最近快照对齐到 Android 系统
trace 的 `CLOCK_BOOTTIME`。因此长时采集和 suspend/resume 不再依赖启动时的一次固定偏移。

该模式不读取或写出包体；内核对象地址会先按本次会话加盐哈希。逻辑 `packet_id`
使用五元组和 TCP seq/ack/flags 关联 skb clone 前后的发送阶段，匿名 `skb_id` 只用于观察
buffer 生命周期。socket lifetime 在 `tcp_close` 或采集结束时闭合。

为避免无边界的全机追踪，必须指定 `--uid`、`--pid`、地址/端口/协议过滤之一，或显式使用
`--force`。单独 `--uid 0` 仍然过宽，必须再加 `--pid`/包过滤，或明确使用 `--force`。

已 root Android 设备可以直接通过 Anettrace 生成一个联合 trace。默认输出到当前目录，文件名为
`anettrace-<时间>.pftrace`，默认时长为 10 秒：

```shell
adb shell
cd /data/local/tmp
./anettrace --capture-trace --uid 10187
```

`--capture-trace` 只生成联合 `.pftrace`，不会再把网络事件逐条打印到终端，也不会隐式开启
`--trace`。`--trace` 是独立终端诊断模式，两者不能在同一个进程组合。确需边抓文件边看终端时，
使用相同过滤条件分别启动两个 Anettrace 进程：

```shell
./anettrace --capture-trace --duration 15 --uid 10187 \
  --output /data/local/tmp/browser-network.pftrace &
./anettrace --trace tcp --uid 10187
```

详细网络函数模式：

```shell
./anettrace --capture-trace --trace-detail --uid 10187
```

设置采集时长和最终文件：

```shell
./anettrace \
  --capture-trace \
  --duration 15 \
  --uid 10187 \
  --output /data/local/tmp/browser-network.pftrace
```

设备端直采默认使用 `full` 系统 profile：以 PerfAllInOne
`start_full_perfetto_trace_10s.bat` 对应的 `perfetto_cfg.pbtx` 为基线，再向同一份原生 Perfetto
trace 追加 Anettrace 网络 TrackEvent。它包含全部应用的 atrace tag、Binder/AIDL 关系、调度和
唤醒、CPU/GPU 频率与 idle、进程/内存统计、GPU memory、FrameTimeline 和 statsd 数据。
如只需要低开销线程状态，可显式使用 `--trace-profile sched`：

```shell
./anettrace \
  --capture-trace \
  --trace-profile sched \
  --duration 15 \
  --uid 10187 \
  --output /data/local/tmp/browser-network-sched.pftrace
```

`--output` 既可以是 `.pftrace` 文件，也可以是已经存在的目录；如果是目录，Anettrace 会在其中
生成带时间戳的文件。已有目标文件不会被覆盖。成功结束后只保留一个最终文件，其中同时包含：

- `full` 默认档的线程 Running 下 atrace tag、Binder/AIDL 调用关系及完整系统性能信息；
- `sched_switch`、`sched_waking`、进程信息和 suspend/resume 等线程状态基础事件；
- socket allocation/lifetime/state；
- `tcp_sendmsg` 返回字节以及 TCP/IP、设备队列、NIC driver 和释放/drop 的逐阶段事件；
- TCP IPv4/IPv6 的 NAPI/L2、IP、transport RX 阶段，以及应用 `tcp_recvmsg` 读取区间；
- UDP 仅采集明文 DNS（源或目标端口 53）的 TX/RX、`udp/udpv6 sendmsg/recvmsg`
  调用区间及实际返回字节；
- 真实执行上下文 TID/TGID/UID、socket owner TID/TGID/UID、方向、CPU、网卡、端点和匿名
  packet/socket ID。

Anettrace 会直接写原生 Perfetto TrackEvent protobuf，保留 BPF `CLOCK_MONOTONIC` 时间戳，再与
Android 系统 Perfetto trace 合并；设备端不需要 Python。临时 system/network/config 文件在成功
或失败后都会清理。完成后直接拉取并打开：

```shell
adb pull /data/local/tmp/browser-network.pftrace .
```

直接模式要求设备存在 `/system/bin/perfetto`。`--capture-trace`、`--perfetto-events` 和终端
`--trace` 是独立模式；`--capture-trace` 不能与后两者在同一进程组合。建议始终使用 UID 或 TID
过滤；`--uid 0` 仍需叠加更窄过滤或 `--force`。

需要 `light/long` profile、simpleperf、外部主机工具、manifest 或自动 Trace Processor 完整性门禁
时，继续使用跨平台 Python 编排器：

```shell
python tools/capture_android_trace.py \
  --uid 10000 \
  --duration 10 \
  --anettrace src/anettrace \
  --out output/perfetto-demo
```

`tools/capture_android_perfetto.sh` 保留为 Linux 兼容入口，内部调用同一个 Python 编排器。
设备端 `full` 直采为了保留线程下的 atrace tag，会按 PerfAllInOne 基线采集全局
`ftrace/print`；这比 `sched` 档开销和输出体积更大。把最终文件拖入
[Perfetto UI](https://ui.perfetto.dev/) 后，发包时间点位于实际执行线程轨道，线程
Running/Runnable/Sleeping 状态来自系统 sched 数据。`--capture-trace` 不打印逐包终端事件；需要
同步查看时另启 `--trace GROUP` 进程。RX 内核事件保留 NAPI/softirq 的真实线程轨道，应用线程只显示
`recvmsg` duration slice，避免把所有收包箭头伪装到 reader 线程下。

每个 packet instant event 使用按本次 trace 首次出现顺序生成的可读名称作为事件名：TCP、
普通 UDP 和 DNS 分别独立编号为 `tcp-1`、`udp-1`、`dns-1`。完整 64 位 `flow_id` 仍写入
Perfetto `correlation_id`，因此同一条流的 TX/RX 和不同内核阶段显示相同名称并使用同一颜色；
精简模式的 `stage` 使用 `TCP SYN send`、`TCP packet receive`、`DNS query send` 等语义名称，
`--trace-detail` 下则保留原内核函数名，完整五元组始终可精确检索。

同一 flow 还使用 Perfetto 原生 Flow 链接串起 `flow start -> packet anchor -> ... -> flow end`。
精简模式下每个实际 TX/RX 包只有一个语义 anchor，选中任一 `tcp-N`/`dns-N` packet event 时会显示
指向前一个和后一个包的箭头，可沿箭头端点在跨线程的收发包之间跳转。详细模式只把 transport
边界事件作为 anchor，避免把每个内核函数 stage 都接入包间导航链；原有 `packet_id` Flow 仍单独
负责串起同一个包的详细内核阶段。

每条五元组还会生成独立的 `anettrace.flow` duration track，并作为对应 socket track 的子轨道
显示，而不是把并发请求都堆在公共网络线程上。socket lifetime 表示内核 socket 对象的存活区间；
flow 表示一条五元组活动区间，一个 UDP socket 可以有多条 flow，因此二者只做层级合并、不合成
同一条 slice。flow 结束点包含 `duration_ns`、`byte_scope=application_payload`、TX/RX 字节、
TX/RX 包数、owner、两端地址端口、
`end_reason` 和 `incomplete`：TCP 在 `tcp_close` 结束，DNS/UDP 在 5 秒空闲后结束，采集窗口内
未自然结束的流在 `trace_end` 截断。同一线程交替处理多条 TCP/DNS 流时，可直接按
`tcp-N`/`dns-N` 名称、颜色和独立 flow track 区分。编号仅在单次 trace 内有效，每次采集从 1
重新开始；当前采集范围中的 UDP 仅包含 DNS/53，普通 `udp-N` 已预留给后续 UDP 扩展。

当前 UDP 范围刻意限制为传统 DNS/53；QUIC/HTTP3（通常为 UDP/443）不在本阶段采集范围内。

编排器吸收了 PerfAllInOne 中仍适合当前链路的抓取能力，但不依赖它附带的 Python 2、exe 或
私有转换器：

| `--profile` | 用途 | 默认时长 |
| --- | --- | ---: |
| `sched` | 低开销调度、进程和 suspend 对齐，默认档 | 10 秒 |
| `light` | PerfAllInOne 风格的 atrace 类别集合 | 10 秒 |
| `full` | 增加频率、内存、GPU 和 FrameTimeline 等系统数据 | 20 秒 |
| `long` | 长时 ring buffer、周期落盘和系统统计 | 600 秒 |
| `none` | 不启动系统 Perfetto，只抓 Anettrace 或联动外部工具 | 10 秒 |

例如同时抓完整系统 trace 与目标应用的 simpleperf：

```shell
python tools/capture_android_trace.py \
  --uid 10123 \
  --profile full \
  --simpleperf-app com.example.app \
  --out output/full-with-cpu
```

也可以把任意主机侧工具放到同一生命周期中；`--external-command` 必须是最后一个选项，后面的
参数会按参数数组直接执行，不经过 shell：

```shell
python tools/capture_android_trace.py \
  --uid 10123 \
  --profile none \
  --out output/external-session \
  --external-command python /path/to/tool.py --capture
```

工具统一转发中断、先停止 Anettrace 以确保 `trace_end` 落盘，再停止 companion，并拒绝空文件、
缺失 `clock_snapshot`/`trace_end` 或外部工具提前退出。每次成功或失败都会生成
`session-manifest.json`，记录设备、boot ID、过滤条件、命令、耗时以及各产物的
大小和 SHA-256。输出目录必须是新目录或空目录，避免覆盖历史抓取。
外部命令产生的文件会进入 manifest，但不会被猜测格式或自动拼接；只有编排器自身生成的两份
未压缩原生 Perfetto trace 才允许 raw TracePacket 兼容拼接。若指定的 Trace Processor 支持
`util merge`，则优先使用官方严格合并：

```shell
python tools/capture_android_trace.py \
  --uid 10123 \
  --trace-processor /path/to/trace_processor \
  --out output/strict-session
```

合并完成后必须通过 `tools/perfetto_sql/anettrace_integrity.sql`：网络事件、系统
`thread_state` 和二者重叠都必须存在，时钟无路径、不可关联时钟域和负时间戳丢弃统计必须为零。
任何 Trace Processor `severity='error'` 的输入/导入错误也会使检查失败。结果写入
`merge-integrity.json`；检查失败时不会留下看似可用的 combined 文件。

直接模式由设备端 `perfetto` 产生系统级轨迹，Anettrace 同时产生原生网络 TrackEvent，结束时
合并为一个文件；Python 编排模式则保留 JSONL、转换、manifest 和严格验收能力。因而可在同一时间轴上从
`tcp_sendmsg_locked` 等网络阶段跳到对应 TID 的调度切换，判断延迟来自线程未被调度、内核网络
路径，还是网卡发送之后。它不会替代系统 Perfetto，也不会向系统 trace 写入报文 payload。

如果设备没有系统 `perfetto` 命令，先单独使用 `--perfetto-events` 生成 JSONL 后离线转换；
该结果仅包含 Anettrace 网络轨道，不能提供 Running/Runnable/Sleeping 等调度状态。
当前覆盖 TCP TX/RX 和 UDP 明文 DNS/53 TX/RX；QUIC/HTTP3、稳定 socket cookie、Android
netId/VPN/Fwmark 解释留待后续。

已有其他工具生成系统 `.pftrace` 时，可直接把它和 Anettrace JSONL 严格合并：

```shell
uv run --with perfetto==0.57.2 python tools/merge_trace_with_anettrace.py \
  system.pftrace anettrace-events.jsonl combined.pftrace \
  --trace-processor /path/to/trace_processor
```

该工具记录输入、输出的大小与 SHA-256，并生成 `combined.pftrace.integrity.json`。旧版 Trace
Processor 没有 `util merge` 时，只接受经过 protobuf 校验的两份未压缩原生 Perfetto trace；
systrace text、Chrome JSON、压缩文件或跨设备数据必须使用支持 manifest 的新版 Trace Processor，
不能用 raw 拼接猜测时钟关系。

只做离线转换时：

```shell
uv run --with perfetto==0.57.2 python tools/anettrace_to_perfetto.py \
  anettrace-events.jsonl anettrace.pftrace
```

## 运行要求

- 需要 root 权限以及允许 BPF program load、attach 和内核文件访问的安全策略。
- 默认 CO-RE 构建需要可读的 `/sys/kernel/btf/vmlinux`。
- KPROBE 模式需要内核启用 KPROBES/KPROBE_EVENTS。
- fentry/fexit 模式需要 BPF TRACING、BPF trampoline 和相应函数的 BTF 信息。
- 某个跟踪目标不存在或能力不足时，Anettrace 会跳过该目标或给出错误；构建成功不等于
  已验证目标设备内核。

## 编译

### 1. 安装依赖

Ubuntu/Debian：

```shell
sudo apt update
sudo apt install -y \
  clang gcc llvm make pkg-config python3 python3-yaml \
  libbpf-dev libelf-dev libzstd-dev zlib1g-dev
```

建议使用较新的 clang、libbpf 和 bpftool。Android CI 的可复现环境使用 Ubuntu 22.04
arm64、libbpf 1.6.2、bpftool v7.6.0 和 Linux v6.12 的 UAPI `bpf.h`。

### 2. 默认 BTF 构建

```shell
git clone https://github.com/ron159/Anettrace.git
cd Anettrace

make clean
make -j$(nproc) all

./src/anettrace --version
./tests/source-contracts.sh
```

如果系统 `bpftool` 不可用或版本不合适，可显式指定：

```shell
make BPFTOOL=/absolute/path/to/bpftool all
```

### 3. 无 BTF 内核的兼容构建

兼容构建必须使用目标运行内核对应的头文件：

```shell
make clean
make KERNEL=/path/to/target-kernel COMPAT=1 all
```

`COMPAT=1` 会启用 `NO_BTF`、`NO_GLOBAL_DATA` 和 `INLINE`。这类产物与构建时
指定的内核结构强相关，不应作为跨内核通用二进制发布。

### 4. Android arm64 静态构建

请在 arm64 Linux 环境或 arm64 容器/QEMU 中准备 libbpf 静态库和 bpftool，然后执行：

```shell
make clean
make BPFTOOL=/absolute/path/to/bpftool \
  STATIC=1 TARGET_PLATFORM=android-arm64 all
make BPFTOOL=/absolute/path/to/bpftool \
  STATIC=1 TARGET_PLATFORM=android-arm64 pack
```

默认归档为：

```text
output/anettrace-0.4.0-android-arm64-dual.tar.bz2
```

CI 中的完整依赖安装、静态链接检查和校验和步骤见
`.github/workflows/build-android-arm64.yml`。

### 5. 安装与打包

```shell
# 安装到系统；也会安装 man page 和 bash completion
sudo make PREFIX=/ install

# 生成 output/anettrace-<version>-<platform>-<type>.tar.bz2
make pack
```

## Android 设备验证

```shell
adb push src/anettrace /data/local/tmp/anettrace
adb push tests/android-smoke.sh /data/local/tmp/android-smoke.sh
adb shell chmod 0755 /data/local/tmp/anettrace /data/local/tmp/android-smoke.sh
adb shell su -c '/data/local/tmp/android-smoke.sh /data/local/tmp/anettrace'
```

测试会检查权限、BTF、CLI 契约，并尝试执行最小 ICMP 追踪。SELinux、vendor 内核配置和
模块 BTF 都可能影响实际可用的跟踪点。

## 分支说明

- `master`：推荐使用的双后端分支，包含 KPROBE 兼容路径、TRACING monitor 和
  `--traffic` 线程流量统计。
- `android-tracing`：以 BTF/TRACING 为基线的实验分支，面向具备 fentry/fexit 和
  trampoline 的较新 Android 内核，不在进程内回退到 KPROBE。

## 来源与致谢

Anettrace 源于 [OpenCloudOS 上游项目](https://github.com/OpenCloudOS/nettrace)。
感谢原项目作者和贡献者建立 eBPF 报文追踪、诊断规则与用户态分析框架；本项目在此基础上
持续维护 Anettrace 产品标识、Android arm64 适配、静态制品和设备验证。

项目沿用 Mulan PSL v2，详见 [LICENSE](LICENSE)。
