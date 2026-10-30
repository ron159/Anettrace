# Anettrace

面向 Linux 与 Android 的 eBPF 网络诊断工具：追踪报文与 Socket、定位丢包和延迟、统计线程流量，并将网络事件与系统调度合并为 Perfetto 时间线。

[下载正式版](https://github.com/ron159/Anettrace/releases/latest) · [使用手册](https://github.com/ron159/Anettrace/wiki) · [CLI 参考](https://github.com/ron159/Anettrace/wiki/CLI-Reference) · [问题反馈](https://github.com/ron159/Anettrace/issues)

## 主要功能

- **报文诊断**：IPv4/IPv6、TCP/UDP/ICMP/ARP，地址、端口、UID、TID 等过滤；支持异常路径、内核丢包、RTT 和协议栈延迟分析。
- **流量统计**：按线程与端点统计 TCP/UDP 收发量；交互界面提供速率、累计量、进程汇总和历史回看。
- **Perfetto 采集**：系统与网络联合时间线、精简/极简/详细展示、环形缓冲和自定义配置；支持 Android 仅系统采集。
- **应用链路**：按包名解析 UID，关联 socket / flow / packet / call，按需记录直接唤醒上下文与早期 RX。
- **离线分析**：生成可筛选的 HTML/JSON 性能报告，查看连接、Socket 时序、慢调用和调度，并定位 Perfetto 原始事件；支持独立安装的 AI 分析 Skill。
- **TCP 建连诊断**：主机工具采集 Android 应用连接证据并生成诊断报告。

## 快速开始

### Android arm64

```sh
version=0.8.15
curl -fLO "https://github.com/ron159/Anettrace/releases/download/v${version}/anettrace-${version}-android-arm64-dual"
curl -fLO "https://github.com/ron159/Anettrace/releases/download/v${version}/SHA256SUMS"
grep " anettrace-${version}-android-arm64-dual$" SHA256SUMS | shasum -a 256 -c -
adb push "anettrace-${version}-android-arm64-dual" /data/local/tmp/anettrace
adb shell chmod 0755 /data/local/tmp/anettrace
adb shell /data/local/tmp/anettrace --version
```

在设备 root shell 中采集目标 UID 的网络与系统时间线：

```sh
cd /data/local/tmp
./anettrace --capture-trace --uid 10187 --duration 15 --output app-network.pftrace
```

将 `10187` 换成目标应用 UID，再在主机拉取文件，用 [Perfetto UI](https://ui.perfetto.dev/) 打开：

```sh
adb pull /data/local/tmp/app-network.pftrace .
```

### Linux

安装构建依赖后运行（见[编译与设备要求](https://github.com/ron159/Anettrace/wiki/Build-and-Device-Requirements)）：

```sh
git clone https://github.com/ron159/Anettrace.git
cd Anettrace
make -j$(nproc) all
sudo ./src/anettrace --proto icmp --detail
```

### 主机离线分析

在源码仓库中运行，Python 3.10+：

```sh
python3 -m venv .venv
.venv/bin/pip install -r skills/anettrace-analysis/requirements.txt
.venv/bin/python skills/anettrace-analysis/scripts/network_report.py inspect capture.pftrace
.venv/bin/python skills/anettrace-analysis/scripts/network_report.py analyze capture.pftrace --out report --serve --open
```

生成 `report/report.html` 和 `report/report.json`。支持按 UID、流、Socket、协议、端点、调用耗时及时间窗组合筛选；AI 安装与使用见[独立分析 Skill](https://github.com/ron159/Anettrace/wiki/Analysis-Skill)。分析能力随 Skill 更新，无需重新编译采集器。

## 常用命令

以下命令在设备 root shell 中运行：

```sh
# 交互流量：速率、累计量和历史
./anettrace --traffic-ui --proto tcp --uid 10187 --interval 1

# 极简网络标签
./anettrace --capture-trace --trace-tags --uid 10187 --duration 15 --output tags.pftrace

# 持续抓取，Ctrl+C 后保存最近 30 秒
./anettrace --capture-trace --ring-buffer --uid 10187 --duration 30 --output recent.pftrace
```

仅系统采集可在有 Perfetto 访问权限的 `adb shell` 中运行，无需 root：

```sh
adb shell /data/local/tmp/anettrace --capture-trace --system-trace-only \
  --duration 10 --output /data/local/tmp/system.pftrace
```

## 必要说明

- 网络追踪需要 root、BPF 加载/挂载权限及目标内核支持；默认 CO-RE 构建需要 `/sys/kernel/btf/vmlinux`。用 `anettrace -t '?'` 查看可用追踪点。
- `--tid`（兼容旧 `--pid`）按精确线程过滤；主机采集工具的 `--package` 可解析应用 UID。
- 默认网络展示为精简模式；`--trace-tags` 为极简模式，`--trace-detail` 展开可用探针。`--trace-profile` 选择系统数据源，`--detail` 增加字段。
- 离线报告需要含 Anettrace 网络事件的轨迹；首次运行可能下载 Trace Processor，离线时指定 `--trace-processor`。交互筛选与 Perfetto 定位需本地服务；按 Ctrl+C 停止。
- 流量按成功收发返回量统计，调用耗时含阻塞与调度等待；两者分别区别于线上字节数和网络 RTT。轨迹与报告包含地址、端口及线程等诊断信息。

## 文档

| 主题 | 入口 |
| --- | --- |
| 安装与参数 | [快速开始](https://github.com/ron159/Anettrace/wiki/Quick-Start) · [CLI 参考](https://github.com/ron159/Anettrace/wiki/CLI-Reference) · [构建要求](https://github.com/ron159/Anettrace/wiki/Build-and-Device-Requirements) |
| 实时诊断 | [报文追踪](https://github.com/ron159/Anettrace/wiki/Packet-Tracing-and-Diagnostics) · [流量统计](https://github.com/ron159/Anettrace/wiki/Traffic-Statistics) · [TCP 建连诊断](https://github.com/ron159/Anettrace/wiki/TCP-Connect-Diagnostics) |
| 采集与链路 | [Perfetto 采集](https://github.com/ron159/Anettrace/wiki/Perfetto-Trace-Capture) · [应用链路采集](https://github.com/ron159/Anettrace/wiki/Application-Flow-Capture) · [链路分析](https://github.com/ron159/Anettrace/wiki/Perfetto-Chain-Analysis) |
| 离线报告与 AI | [收发性能报告](https://github.com/ron159/Anettrace/wiki/Network-Performance-Report) · [独立分析 Skill](https://github.com/ron159/Anettrace/wiki/Analysis-Skill) |
| 排障与源码说明 | [常见问题](https://github.com/ron159/Anettrace/wiki/Troubleshooting) · [抓取缓冲区与丢事件](docs/capture-buffers.md) · [仓库文档](docs/) |

## 来源与许可

推荐使用 `master`；`android-tracing` 为 TRACING-only 实验分支。项目源于 [OpenCloudOS/nettrace](https://github.com/OpenCloudOS/nettrace)，采用 [Mulan PSL v2](LICENSE)。
