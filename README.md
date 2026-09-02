# Anettrace

Anettrace 是面向 Linux 与已 root Android 设备的 eBPF 网络诊断工具，可追踪报文在内核协议栈中的路径、定位丢包和延迟、统计线程流量，并生成包含网络与系统调度信息的 Perfetto 时间线。

> 当前正式版：**v0.6.2**。完整安装说明、参数解释、模式组合、Android 抓取和排障指南已经移至 [GitHub Wiki](https://github.com/ron159/Anettrace/wiki)。

[下载 v0.6.2](https://github.com/ron159/Anettrace/releases/tag/v0.6.2) · [使用手册](https://github.com/ron159/Anettrace/wiki) · [CLI 完整参考](https://github.com/ron159/Anettrace/wiki/CLI-Reference) · [问题反馈](https://github.com/ron159/Anettrace/issues)

## 主要功能

- 报文生命周期追踪：IPv4、IPv6、TCP、UDP、ICMP、ARP 等协议；
- 地址、端口、协议、网络命名空间、TID、UID 等组合过滤；
- `--diag` 异常路径分析与 `--drop` 内核丢包定位；
- TCP RTT、协议栈延迟、Socket 生命周期和 monitor 模式；
- `--traffic` 按线程与 flow 统计 TCP/UDP 应用层收发字节；
- `--capture-trace` 生成系统 Perfetto 与网络事件联合时间线；
- `--ring-buffer` 持续抓取并在停止时保存最近 N 秒；
- Android TCP 主动建连根因诊断与隐私受控报告。

## 快速开始

### Android arm64 正式版

```shell
curl -LO https://github.com/ron159/Anettrace/releases/download/v0.6.2/anettrace-0.6.2-android-arm64-dual
curl -LO https://github.com/ron159/Anettrace/releases/download/v0.6.2/SHA256SUMS
grep 'anettrace-0.6.2-android-arm64-dual$' SHA256SUMS | shasum -a 256 -c -

adb push anettrace-0.6.2-android-arm64-dual /data/local/tmp/anettrace
adb shell chmod 0755 /data/local/tmp/anettrace
adb shell /data/local/tmp/anettrace --version
```

运行追踪需要 root。若 `adbd` 不是 root，请使用你已经信任并验证过的设备端提权方式；工具不会自动尝试 `adb root`、`su` 或 Magisk。

### Linux 源码构建

```shell
git clone https://github.com/ron159/Anettrace.git
cd Anettrace
make -j$(nproc) all
sudo ./src/anettrace --proto icmp --detail
```

依赖安装、无 BTF 兼容构建和 Android 静态打包见 [编译与设备要求](https://github.com/ron159/Anettrace/wiki/Build-and-Device-Requirements)。

## 常用命令

```shell
# 查看目标内核实际可用的追踪组和函数
sudo ./src/anettrace -t '?'

# 诊断指定地址的异常路径
sudo ./src/anettrace --diag --addr 192.0.2.10

# 按 UID 查看 TCP 应用层流量
sudo ./src/anettrace --traffic --proto tcp --uid 1000 --interval 2

# 使用设备上的自定义 Perfetto textproto 配置联合抓取
./anettrace --capture-trace \
  --perfetto-config /data/local/tmp/perfetto_cfg.pbtxt \
  --duration 10 --uid 10187 \
  --output /data/local/tmp/custom-network.pftrace

# 后台持续抓取，Ctrl+C 后保存停止前 30 秒，同时显示流量
./anettrace --traffic --capture-trace --ring-buffer \
  --duration 30 --interval 2 --proto tcp --uid 10187 \
  --output /data/local/tmp/browser-network.pftrace
```

`--perfetto-config` 与 `--trace-profile` 互斥。自定义配置中的顶层 `duration_ms`
会被忽略，普通模式统一使用 `--duration` 管理采集窗口，环形模式持续到 Ctrl+C。
配置必须是设备上的非空普通文件，大小不超过 4 MiB。

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
| [常见问题](https://github.com/ron159/Anettrace/wiki/Troubleshooting) | 参数冲突、BTF、probe、ADB 和输出排障 |

## 运行要求

- root 权限和允许 BPF program load/attach 的安全策略；
- 默认 CO-RE 构建需要可读的 `/sys/kernel/btf/vmlinux`；
- KPROBE、BPF TRACING、tracepoint 和 Perfetto 能力由具体模式决定；
- 构建成功不代表目标 Android vendor 内核支持全部跟踪点。

请先执行 `anettrace --version`、`anettrace -h` 和 `anettrace -t '?'`，再根据目标设备能力选择模式。

## 分支、来源与许可

- `master`：推荐使用的双后端产品分支；
- `android-tracing`：TRACING-only 实验分支，不在进程内回退到 KPROBE。

Anettrace 源于 [OpenCloudOS/nettrace](https://github.com/OpenCloudOS/nettrace)，感谢原项目作者和贡献者建立 eBPF 报文追踪与诊断框架。

项目采用 [Mulan PSL v2](LICENSE)。
