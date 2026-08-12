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
- **TCP 主动建连根因诊断**：按应用 UID 关联 `connect()`、Socket 状态、RST、重传、drop、
  RTT 和调度证据，生成受约束的自动结论、公开 JSON 报告与同一份 Perfetto 时间线。

## 常用示例

完整参数按功能分组显示，以 `./src/anettrace --help` 为准。以下 Linux 示例使用源码构建路径；
Android 示例假设静态二进制已经放到 `/data/local/tmp/anettrace`。

### 终端网络诊断

```shell
# 跟踪 ICMP 报文的内核路径
sudo ./src/anettrace --proto icmp --detail

# 诊断指定地址的异常报文
sudo ./src/anettrace --diag --addr 192.0.2.10

# 监控丢包并显示内核栈
sudo ./src/anettrace --drop --drop-stack

# 查看当前内核实际可用的追踪目标
sudo ./src/anettrace -t "?"

# 只在终端跟踪 TCP 组；不会启动 Perfetto
sudo ./src/anettrace --trace tcp --uid 1000
```

### 流量统计

```shell
# 每 2 秒输出指定 UID 的 TCP 应用层收发字节
sudo ./src/anettrace --traffic --proto tcp --uid 1000 --interval 2
```

`--traffic` 显示 `APP_TX_KB/APP_RX_KB`，统计的是应用 send/recv 成功返回的 payload，不等同于
Wireshark 的链路层字节数。

### Android：一键诊断 TCP 主动建连

使用与当前源码 commit 匹配的 Android arm64 dual 二进制和 Trace Processor，在主机执行：

```shell
python3 tools/diagnose_android_connect.py \
  --package com.example.app \
  --binary /path/to/anettrace-0.5.0-android-arm64-dual \
  --trace-processor /path/to/trace_processor_shell \
  --out output/connect-report
```

默认最长 120 秒、最大 512 MiB，使用 `sched` profile。设备的 ADB shell 必须已经是 root；工具
不会自动执行 `adb root`、`su` 或 Magisk 命令。输出目录包含 `report.md`、`report.json`、
`manifest.json`、`trace.pftrace`、`session.log` 和 `SHA256SUMS`。

报告默认保留诊断所需的 IP、端口、UID/TID 和匿名 Socket ID，但不持久化包名、设备序列号、
payload、URL、Header、SNI 或 DNS 内容。只有显式添加 `--include-package` 才会写入包名和
shared UID 候选。完整 outcome、能力门控和隐私契约见
[`docs/connect-diagnostics.md`](docs/connect-diagnostics.md)。

### Android：直接抓取系统 Trace 与网络事件

默认抓取 10 秒、使用 `full` 系统 profile 和精简网络模式，最终在当前目录生成一个
`anettrace-<时间>.pftrace`：

```shell
adb shell
cd /data/local/tmp
./anettrace --capture-trace --uid 10187
```

设置抓取时长和输出文件：

```shell
./anettrace \
  --capture-trace \
  --duration 15 \
  --uid 10187 \
  --output /data/local/tmp/browser-network.pftrace
```

抓取完成后拉取并用 Perfetto UI 打开：

```shell
adb pull /data/local/tmp/browser-network.pftrace .
```

`--output` 可以是新的 `.pftrace` 文件，也可以是已经存在的目录；已有目标文件不会被覆盖。
必须提供 UID、TID、地址、端口或协议过滤之一，只有明确需要全机采集时才使用 `--force`。

### Android：低开销或详细网络模式

```shell
# 只保留 sched/wakeup 等线程状态，降低系统 trace 开销
./anettrace --capture-trace --trace-profile sched --duration 15 \
  --uid 10187 --output /data/local/tmp/browser-network-sched.pftrace

# 在默认 full 系统 trace 上记录完整 TCP/IP、qdisc、NIC、skb clone/free 函数链
./anettrace --capture-trace --trace-detail --duration 15 \
  --uid 10187 --output /data/local/tmp/browser-network-detail.pftrace
```

默认精简模式只保留 socket、TCP 状态、应用 I/O、TCP 关键包和 DNS 收发点；
`--trace-detail` 只改变网络事件粒度，不改变 `full`/`sched` 系统 profile。

### 同时抓文件并在终端观察

`--capture-trace` 和 `--trace GROUP` 是独立模式，不能在同一个进程组合。需要同时使用时，以相同
过滤条件启动两个进程：

```shell
./anettrace --capture-trace --duration 15 --uid 10187 \
  --output /data/local/tmp/browser-network.pftrace &
./anettrace --trace tcp --uid 10187
```

结束终端进程不会隐式停止文件采集，反之亦然。

### 配合已有系统 Trace 工具

如果系统 trace 由其他工具抓取，Anettrace 只导出网络 JSONL，之后在主机侧转换、合并：

```shell
# 设备端：与外部 trace 使用相同的抓取时间窗口
./anettrace --uid 10000 \
  --perfetto-events /data/local/tmp/anettrace-events.jsonl

# 主机端：先转换网络事件，再与外部系统 trace 合并
uv run --with perfetto==0.57.2 python tools/anettrace_to_perfetto.py \
  anettrace-events.jsonl anettrace.pftrace
uv run --with perfetto==0.57.2 python tools/merge_trace_with_anettrace.py \
  system.pftrace anettrace.pftrace combined.pftrace \
  --trace-processor /path/to/trace_processor
```

需要自动管理 Perfetto、simpleperf、外部命令、manifest 和完整性检查时，使用主机编排器：

```shell
python tools/capture_android_trace.py \
  --uid 10123 \
  --profile full \
  --simpleperf-app com.example.app \
  --out output/full-with-cpu
```

`--perfetto-events` 只包含 Anettrace 网络轨道；线程 Running/Runnable/Sleeping 状态必须来自系统
Perfetto。所有模式都不抓取或保存 packet payload。

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

`--traffic` 是独立统计通路：它在 TCP/UDP send/recv 的入口保存调用上下文，
在返回点按真实返回值累计字节，因此 `APP_TX_KB/APP_RX_KB` 显示的是可归属到线程的应用
payload，不包含协议头、SYN/ACK/FIN、重传、纯内核转发，以及尚未被应用读取的数据。收到
Ctrl-C 时会先打印最后一个未满统计区间。联合采集不需要也不会启动这套独立 skeleton；
`--capture-trace` 自身会在 `tcp/udp/udpv6 sendmsg/recvmsg` 返回点统计实际字节，并写入对应的
五元组 flow。两个模式不能在同一个进程组合，但可以分别启动两个 Anettrace 进程独立使用。

### Perfetto 数据模型

`--capture-trace` 同时运行 Android 系统 Perfetto 和 Anettrace 原生 TrackEvent 编码器，结束时合并为
一个 `.pftrace`。默认 `full` profile 保留 atrace/Binder、sched/wakeup、CPU/GPU 与进程统计；
`sched` profile 只保留较低开销的线程调度基础数据。具体命令集中在“常用示例”。

网络侧记录 socket 创建/状态、应用 I/O、TCP TX/RX 和 UDP DNS/53 TX/RX 元数据，不读取 packet
payload。事件保留真实执行线程，并用周期时钟快照把 BPF `CLOCK_MONOTONIC` 对齐到系统 trace；
NAPI/softirq RX 不会被伪装到应用 reader 线程。

同一五元组使用 `tcp-N`、`dns-N` 或 `udp-N` 名称和独立 flow lifetime track。`flow_id` Flow 串起
同流连续收发包，便于在 Perfetto 中沿箭头跳转；`packet_id` Flow 则在详细模式下串起同一个包的
内核阶段。完整 ID 仍保存在事件属性中，可用于精确检索。

`--traffic`、`--capture-trace`、终端 `--trace GROUP` 和 JSONL `--perfetto-events` 是独立入口。
直采需要设备提供 `/system/bin/perfetto`；JSONL 可与第三方系统 trace 离线合并，但本身不包含
Running/Runnable/Sleeping 等系统调度状态。

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
output/anettrace-0.5.0-android-arm64-dual.tar.bz2
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
