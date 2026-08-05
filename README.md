# Anettrace

Anettrace 是面向 Linux 与已 root Android 设备的 eBPF 网络诊断工具。它直接观察内核中的
`sk_buff`、socket、网络函数和 tracepoint，将报文路径、丢包原因、处理延迟和进程身份
整理为可读的终端输出。

当前 `android-tracing` 分支专注 BTF/TRACING 后端，使用 fentry、fexit 和 tp_btf，
目标是为具备现代 BPF 能力的 Android arm64 内核提供更低开销、参数解析更可靠的追踪路径。
构建产物和命令统一使用 `anettrace`。

## 主要功能

- **报文生命周期追踪**：关联报文进入、处理、克隆、释放和丢弃事件，显示其在内核协议栈
  中经过的函数路径。
- **组合过滤**：支持 IPv4/IPv6 地址、端口、协议、网络命名空间、TID 和 UID；
  `--uid 0` 可正确匹配 root 流量。
- **诊断与丢包分析**：`--diag` 根据 `src/trace.yaml` 的规则识别异常并给出建议；
  `--drop` 在内核提供相应 BTF tracepoint 时输出 skb drop reason。
- **性能分析**：支持函数间延迟、延迟分布、TCP RTT、socket 生命周期和轻量监控模式。
- **Android 诊断字段**：可输出 TID、TGID、UID、CPU、网卡、IPv4 ID、skb mark、
  本地时间或原始单调时间戳。
- **能力感知加载**：启动时检查 BPF TRACING、BTF 和目标函数；不支持的单个追踪点会被
  标记并跳过，权限或整体能力错误会给出明确诊断。

常用示例：

```shell
# 查看当前内核真正可挂载的追踪点以及跳过原因
sudo ./src/anettrace -t "?" --debug

# 跟踪 ICMP 报文路径并显示进程与报文细节
sudo ./src/anettrace --proto icmp --detail

# 诊断指定地址的异常报文
sudo ./src/anettrace --diag --addr 192.0.2.10

# 监控丢包并打印调用栈
sudo ./src/anettrace --drop --drop-stack

# 输出原始单调时间戳，便于和其他 tracing 数据对齐
sudo ./src/anettrace --proto tcp --port 443 --timestamp
```

完整参数以 `./src/anettrace --help` 为准。

## 原理与架构

```text
命令行模式与过滤条件
        |
        v
trace.yaml --gen_trace.py--> 跟踪分组、函数、tp_btf 与诊断规则
        |
        v
读取 vmlinux / module BTF，解析目标函数参数
        |
        v
模板 eBPF 程序 -> 按目标克隆并修正指令 -> fentry / fexit / tp_btf
        |
        v
eBPF 过滤、skb/socket 上下文关联、maps 与 perf events
        |
        v
用户态生命周期聚合 -> 规则匹配 -> 格式化输出
```

核心流程分为五步：

1. **配置生成**：`src/anettrace.c` 解析模式和过滤条件；
   `src/trace.yaml` 描述跟踪分组、目标和诊断规则，
   `src/gen_trace.py` 在构建时生成对应 C 定义。
2. **能力检查**：`src/trace.c` 检查 root 权限、vmlinux BTF、BPF TRACING、
   tracefs/debugfs 和模块 BTF。Android 目标还执行 Linux 6.6+ 门禁。
3. **目标解析**：`src/trace_tracing.c` 从 vmlinux 或模块 BTF 获取函数 ID、
   参数数量以及 skb/socket 参数位置，避免依赖固定寄存器布局。
4. **程序加载**：构建只生成少量模板程序；用户态为每个跟踪目标克隆指令，
   写入 trace 索引与参数偏移，再通过 BPF link 挂载到 fentry、fexit 或 tp_btf。
5. **事件分析**：内核程序完成过滤和上下文关联后通过 perf event map 上报；
   `src/analysis.c` 聚合生命周期并执行规则，`src/output.c` 负责最终展示。

这个分支不会在同一进程内回退到 KPROBE。BPF TRACING 能力不足时，应改用
`master` 分支提供的双后端产物。

## 运行要求

- root 权限；SELinux 必须允许 BPF program load/link、BTF 和相关内核文件访问。
- 可读的 `/sys/kernel/btf/vmlinux`。
- 内核支持 `BPF_PROG_TYPE_TRACING`、fentry/fexit、BPF trampoline 和 BPF link。
- Android 运行目标为 Linux 6.6 或更新内核。
- vendor 模块中的目标需要对应模块 BTF；缺失时只跳过受影响目标。
- tracefs/debugfs 缺失时，核心函数追踪仍可继续，但 drop/reset reason 等能力会降级。

构建和 CI 成功只说明二进制与静态契约正确，不能代替真实目标设备验证。

## 编译

### 1. 安装依赖

此分支需要较新的 libbpf；最低应为 1.4.0，CI 固定使用 libbpf 1.6.2 和
bpftool v7.6.0。

Ubuntu/Debian：

```shell
sudo apt update
sudo apt install -y \
  ca-certificates clang gcc git llvm make pkg-config python3 python3-yaml \
  libelf-dev libzstd-dev zlib1g-dev
```

如果发行版提供 libbpf 1.4.0 或更新版本，也可以直接安装 `libbpf-dev` 与
`bpftool`。否则请按 CI 工作流构建 libbpf 1.6.2 和 bpftool v7.6.0。

### 2. Linux BTF 构建

```shell
git clone --branch android-tracing \
  https://github.com/ron159/Anettrace.git
cd Anettrace

make clean
make BPFTOOL=/absolute/path/to/bpftool -j$(nproc) all

./src/anettrace --version
./tests/source-contracts.sh
sudo ./tests/selftests.sh ./src/anettrace
```

### 3. Android arm64 静态构建

请在 arm64 Linux 环境或 arm64 容器/QEMU 中安装 libbpf 静态库，并执行：

```shell
make clean
make BPFTOOL=/absolute/path/to/bpftool \
  STATIC=1 TARGET_PLATFORM=android-arm64 all
make BPFTOOL=/absolute/path/to/bpftool \
  STATIC=1 TARGET_PLATFORM=android-arm64 pack
```

默认归档为：

```text
output/anettrace-0.4.0-android-arm64-tracing.tar.bz2
```

CI 的完整环境准备、AArch64/静态链接检查、SHA-256 校验和制品回下载验证见
`.github/workflows/build-android-arm64.yml`。

### 4. 安装与打包

```shell
# 安装二进制、man page、bash 和 fish completion
sudo make PREFIX=/ install

# 生成 output/anettrace-<version>-<platform>-tracing.tar.bz2
make pack
```

## Android 设备验证

```shell
adb push src/anettrace /data/local/tmp/anettrace
adb push tests/android-smoke.sh /data/local/tmp/android-smoke.sh
adb shell chmod 0755 /data/local/tmp/anettrace /data/local/tmp/android-smoke.sh

adb shell su -c '/data/local/tmp/anettrace -t "?" --debug'
adb shell su -c '/data/local/tmp/android-smoke.sh /data/local/tmp/anettrace'
```

设备测试会保存权限、BTF、可用目标和最小 ICMP 追踪证据。若失败，应结合 Anettrace
错误输出与 SELinux AVC 日志判断是权限、BTF 缺失、目标不存在还是 TRACING 能力不足。

## 分支说明

- `master`：推荐使用的双后端分支，保留 KPROBE 兼容路径，并包含线程 TCP/UDP
  流量统计。
- `android-tracing`：当前分支，只使用 BTF/TRACING，适合验证现代 Android 内核上的
  fentry/fexit/tp_btf 实现。

## 来源与致谢

Anettrace 源于 [OpenCloudOS 上游项目](https://github.com/OpenCloudOS/nettrace)。
感谢原项目作者和贡献者建立 eBPF 报文追踪、诊断规则与用户态分析框架；本项目在此基础上
持续维护 Anettrace 产品标识、Android arm64 TRACING 适配、静态制品和设备验证。

项目沿用 Mulan PSL v2，详见 [LICENSE](LICENSE)。
