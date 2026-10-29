# Anettrace

Anettrace 是面向 Linux 与 Android 的 eBPF 网络诊断工具，可追踪报文在内核协议栈中的路径、定位丢包和延迟、统计线程流量，并生成包含网络与系统调度信息的 Perfetto 时间线。网络追踪需要 root；Android 也支持通过有 Perfetto 访问权限的 `adb shell` 用户仅采集系统 trace。

> 当前正式版：**v0.8.14**。完整安装说明、参数解释、模式组合、Android 抓取和排障指南见 [GitHub Wiki](https://github.com/ron159/Anettrace/wiki)；离线报告与近期采集能力见下方仓库文档。

[下载 v0.8.14](https://github.com/ron159/Anettrace/releases/tag/v0.8.14) · [使用手册](https://github.com/ron159/Anettrace/wiki) · [CLI 完整参考](https://github.com/ron159/Anettrace/wiki/CLI-Reference) · [问题反馈](https://github.com/ron159/Anettrace/issues)

## 主要功能

- 报文生命周期追踪：IPv4、IPv6、TCP、UDP、ICMP、ARP 等协议；
- 地址、端口、协议、网络命名空间、TID、UID 等组合过滤；
- `--diag` 异常路径分析与 `--drop` 内核丢包定位；
- TCP RTT、协议栈延迟、Socket 生命周期和 monitor 模式；
- `--traffic` 保留逐周期追加的线程流量表；`--traffic-ui` 启用当前速率、累计量、进程汇总及历史回看的交互界面；
- `--capture-trace` 生成系统 Perfetto 与网络事件联合时间线；
- `--system-trace-only` 在有系统 Perfetto 访问权限的 Android shell 中采集系统 trace，无需 root；
- `--ring-buffer` 持续抓取并在停止时保存最近 N 秒；
- Android TCP 主动建连根因诊断与隐私受控报告；
- [独立分析 Skill](docs/analysis-skill.md)：AI 分析已有 pftrace，按 UID、流、socket、协议、端点和耗时组合筛选；单独更新分析能力，无需重新编译采集器。
- [通用收发性能报告与 Perfetto 入口](docs/network-performance-report.md)：离线生成 HTML/JSON，通过五个 Tab 查看采集质量、连接、Socket 创建与 SYN/FIN 时序、慢调用及调度时间；支持 UTC+8 / 相对时间显示，并复用 Perfetto 标签页定位原始 tag。

## 快速开始

### Android arm64 正式版

```shell
version=0.8.14
curl -fLO "https://github.com/ron159/Anettrace/releases/download/v${version}/anettrace-${version}-android-arm64-dual"
curl -fLO "https://github.com/ron159/Anettrace/releases/download/v${version}/SHA256SUMS"
grep " anettrace-${version}-android-arm64-dual$" SHA256SUMS | shasum -a 256 -c -

adb push "anettrace-${version}-android-arm64-dual" /data/local/tmp/anettrace
adb shell chmod 0755 /data/local/tmp/anettrace
adb shell /data/local/tmp/anettrace --version
```

运行 eBPF 网络追踪需要 root。若 `adbd` 不是 root，请使用你已经信任并验证过的设备端提权方式；工具不会自动尝试 `adb root`、`su` 或 Magisk。仅系统采集见下方 `--system-trace-only` 示例。

### Linux 源码构建

```shell
git clone https://github.com/ron159/Anettrace.git
cd Anettrace
make -j$(nproc) all
sudo ./src/anettrace --proto icmp --detail
```

依赖安装、无 BTF 兼容构建和 Android 静态打包见 [编译与设备要求](https://github.com/ron159/Anettrace/wiki/Build-and-Device-Requirements)。

### 在主机生成离线报告

推荐使用可独立更新的 [分析 Skill](docs/analysis-skill.md)，不必等待采集器或 host-tools 发版。旧版报告可继续下载同版本的 `host-tools`，校验后解压；在解压目录运行以下命令。源码仓库可直接从创建虚拟环境开始：

```shell
version=0.8.14
curl -fLO "https://github.com/ron159/Anettrace/releases/download/v${version}/anettrace-${version}-host-tools.tar.bz2"
curl -fLO "https://github.com/ron159/Anettrace/releases/download/v${version}/SHA256SUMS"
grep " anettrace-${version}-host-tools.tar.bz2$" SHA256SUMS | shasum -a 256 -c -
tar -xjf "anettrace-${version}-host-tools.tar.bz2"
cd "anettrace-${version}-host-tools"
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements-perfetto.txt
.venv/bin/python tools/network_report.py analyze /path/to/capture.pftrace --out report --serve --open
```

报告读取已有 Anettrace `.pftrace`，无需设备或重新采集，生成 `report/report.html` 和
`report/report.json`。服务仅监听 `127.0.0.1`，按 Ctrl+C 停止。首次分析可能下载
Trace Processor；离线使用、恢复服务与统计边界见[报告说明](docs/network-performance-report.md)。
仅系统 trace 不包含 Anettrace 网络事件，不能单独用于生成该报告。

## 常用命令

```shell
# 查看目标内核实际可用的追踪组和函数
sudo ./src/anettrace -t '?'

# 诊断指定地址的异常路径
sudo ./src/anettrace --diag --addr 192.0.2.10

# 按 UID 查看 TCP 应用层流量（原有逐周期表格）
sudo ./src/anettrace --traffic --proto tcp --uid 1000 --interval 2

# 新界面：保留空闲线程、显示时间，按 h 回看最近 60 次采样
sudo ./src/anettrace --traffic-ui --proto tcp --uid 1000 --interval 1

# 使用设备上的自定义 Perfetto textproto 配置联合抓取
./anettrace --capture-trace \
  --perfetto-config /data/local/tmp/perfetto_cfg.pbtxt \
  --duration 10 --uid 10187 \
  --output /data/local/tmp/custom-network.pftrace

# 极简展示：socket 创建、应用调用和收发包；点击 packet 保留完整参数
./anettrace --capture-trace --trace-tags --uid 10187 \
  --duration 10 --output /data/local/tmp/network-tags.pftrace

# 后台持续抓取，Ctrl+C 后保存停止前 30 秒，同时显示流量
./anettrace --traffic --capture-trace --ring-buffer \
  --duration 30 --interval 2 --proto tcp --uid 10187 \
  --output /data/local/tmp/browser-network.pftrace

# 仅系统 trace：在 adb shell 中运行，无需 su，不加载 BPF
./anettrace --capture-trace --system-trace-only --duration 10 \
  --output /data/local/tmp/system.pftrace

# 仅系统 trace 也可使用自定义配置
./anettrace --capture-trace --system-trace-only \
  --perfetto-config /data/local/tmp/perfetto_cfg.pbtxt \
  --duration 10 --output /data/local/tmp/custom-system.pftrace
```

`--traffic-ui` 已包含 `--traffic`，也支持与后台 `--capture-trace` 联用。输出重定向或
`TERM=dumb` 时自动使用旧表格；完整操作与统计限制见[流量概览说明](docs/traffic-overview-experiment.md)。

增加 `--trace-tags` 使用**极简模式**：显示 socket 创建、应用网络调用和关键收发包，
保留 packet 的 `socket_id`、`ip_id`、端点和关联字段，隐藏箭头、socket I/O 切片及重复概览。
主机采集工具也支持此选项；已有 JSONL 可用 `tools/anettrace_to_perfetto.py --trace-tags` 转换。

网络采集默认使用**精简模式**，显示 socket 创建/关闭、应用收发、TCP 握手和
关键包事件。增加 `--trace-detail` 切换为**详细模式**，显示探针目录支持且设备
可挂载的网络路径阶段。两种模式使用相同的 socket、flow、包和调用关联字段；
`--trace-profile full/sched` 只选择系统 Perfetto 数据源，不切换网络详细程度。
`--detail` 仅增加事件附加字段；`--force` 放宽无过滤或宽泛 UID 0 的采集检查，
保留已有过滤条件，也不切换精简/详细模式。完整参数与示例见 `anettrace -h`。

应用线程下的 `Network syscalls` 轨道记录收发调用的起止、fd、flags、返回值和错误，
包括 socket `read/write/readv/writev`、批量收发以及支持的兼容 ABI；不包含 libc
用户态入口。批量调用的返回值按消息数解释。调用耗时包含阻塞和调度等待，
不代表对端收包耗时；采集结束时仍未返回的调用标为 `incomplete`。
这层不额外累加流量，也不在纯系统采集或连接专项诊断模式中启用。

按 `flow_id` 查看连接，按 `packet_id` 跟踪一个 skb，再通过 `io_id/call_id`
定位实际收发调用。完整操作、SQL 查询和关联边界见
[Perfetto 收发链路分析](docs/perfetto-chain.md)。

主机采集支持 `--package` 精确解析应用 UID；`--tid` 明确表示线程过滤，兼容旧
`--pid`。可按需开启 `--wakeup-chain` 记录调用入口的直接唤醒与运行上下文，开启
`--rx-context` 在同一 skb 获得可靠 socket 证据后补全早期 RX。用法、额外开销和
证据边界见[应用收发链路采集](docs/packet-flow-foundations.md)。

`--system-trace-only` 必须与 `--capture-trace` 一起使用，跳过 root 检查、BPF 探测、
挂载和所有 Anettrace 网络事件导出。支持 `--duration`、`--output`、`--trace-profile`、
`--perfetto-config` 和 `--ring-buffer`。不接受 `--uid`、`--pid`、`--traffic`、
`--trace-detail` 等网络过滤、分析或 BPF 参数；系统采集范围由 Perfetto 配置决定。
这里的无需 root 是指使用有系统 Perfetto 访问权限的 `adb shell` 用户，并不保证普通
Android 应用身份可采集。设备 ROM 仍可能限制某些数据源。Android 版将配置临时写入
`/data/misc/perfetto-configs`，由 Perfetto 自行在 `/data/misc/perfetto-traces` 创建
trace，避免 SELinux 拒绝访问输出目录或继承的文件描述符。采集完成后，由 Anettrace
读取并保存到 `--output` 指定的路径，清理本次配置和 trace 临时文件；最终输出目录
只需调用者可写，无需 Perfetto 可写。自定义配置仍可放在 `/data/local/tmp`。
若自定义配置自身启用了系统网络数据源，这些系统事件仍由 Perfetto 正常采集。

启动前会探测设备 Perfetto 的 `--help`。支持 `--notify-fd` 时等待数据源启动确认；
旧版不支持时自动使用前台采集，并提示无法确认数据源就绪，采集时长从进程启动后计算。
兼容模式仍监控子进程、处理 Ctrl+C，并拒绝错误退出或空 trace。能力探测失败或超时，
以及已支持 `--notify-fd` 时的确认失败，均会报错，不会静默降级。

`--perfetto-config` 与 `--trace-profile` 互斥。自定义配置中的顶层 `duration_ms`
会被忽略，普通模式统一使用 `--duration` 管理采集窗口，环形模式持续到 Ctrl+C。
配置必须是设备上的非空普通文件，大小不超过 4 MiB。

从 0.6.5 起，所有导出的网络事件附加参数直接保存为字符串，每个参数只显示一份，
不再添加 0.6.4 Release 中的 `debug.search.*` 副本，简洁的流标签保持不变。
在 Perfetto 顶部搜索框输入值（如 `443`、`0x1234`、`false`）或字段名（如 `dport`），
即可检索对应事件。搜索为文本匹配，不支持将 `dport=443` 自动解析为字段过滤。
需要精确筛选时使用 SQL：`EXTRACT_ARG(arg_set_id, 'debug.dport') = '443'`；
数值比较、排序或统计前使用 `CAST(EXTRACT_ARG(arg_set_id, 'debug.dport') AS INT)`。
布尔值为字符串 `true`/`false`，使用字符串比较，不要直接转为整数。
`dport` 表示当前包的目的端口，收包时通常是手机本地端口。
已有 trace 需重新抓取，或用新版转换工具重新转换原始 JSONL。

完整参数以 `anettrace -h` 和 [CLI Wiki](https://github.com/ron159/Anettrace/wiki/CLI-Reference) 为准。

## 使用文档

| 文档 | 内容 |
| --- | --- |
| [快速开始](https://github.com/ron159/Anettrace/wiki/Quick-Start) | 下载、校验、部署和第一次追踪 |
| [CLI 完整参考](https://github.com/ron159/Anettrace/wiki/CLI-Reference) | 全部公开参数、默认值与组合规则 |
| [报文追踪与诊断](https://github.com/ron159/Anettrace/wiki/Packet-Tracing-and-Diagnostics) | default、basic、diag、drop、RTT、latency |
| [线程流量统计](https://github.com/ron159/Anettrace/wiki/Traffic-Statistics) | 统计口径、过滤范围和组合抓取 |
| [Perfetto 与环形缓冲](https://github.com/ron159/Anettrace/wiki/Perfetto-Trace-Capture) | 固定时长、环形抓取、JSONL 转换和合并 |
| [TCP 建连诊断](https://github.com/ron159/Anettrace/wiki/TCP-Connect-Diagnostics) | 自动结论、报告、隐私边界和中断恢复 |
| [离线收发性能报告](docs/network-performance-report.md) | HTML/JSON、Socket 时间线、时间显示与 Perfetto 定位 |
| [应用收发链路采集](docs/packet-flow-foundations.md) | 应用过滤、直接唤醒上下文、早期 RX 与证据边界 |
| [Perfetto 收发链路分析](docs/perfetto-chain.md) | socket / flow / packet / call 关联和 SQL |
| [交互式流量概览](docs/traffic-overview-experiment.md) | 当前速率、累计流量、历史回看和统计限制 |
| [常见问题](https://github.com/ron159/Anettrace/wiki/Troubleshooting) | 参数冲突、BTF、probe、ADB 和输出排障 |

## 运行要求

- eBPF 网络追踪需要 root 权限和允许 BPF program load/attach 的安全策略；
- tracefs 可挂载于 `/sys/kernel/tracing`，也兼容 `/sys/kernel/debug/tracing`；
- 默认 CO-RE 构建需要可读的 `/sys/kernel/btf/vmlinux`；
- KPROBE、BPF TRACING、tracepoint 和 Perfetto 能力由具体模式决定；
- 构建成功不代表目标 Android vendor 内核支持全部跟踪点。

仅系统采集依赖设备 Perfetto 的权限和数据源；主机离线报告需要 Python 环境，均无需加载 BPF。

请先执行 `anettrace --version`、`anettrace -h` 和 `anettrace -t '?'`，再根据目标设备能力选择模式。

## 分支、来源与许可

- `master`：推荐使用的双后端产品分支；
- `android-tracing`：TRACING-only 实验分支，不在进程内回退到 KPROBE。

Anettrace 源于 [OpenCloudOS/nettrace](https://github.com/OpenCloudOS/nettrace)，感谢原项目作者和贡献者建立 eBPF 报文追踪与诊断框架。

项目采用 [Mulan PSL v2](LICENSE)。
