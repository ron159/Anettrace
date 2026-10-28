# 通用收发性能报告与 Perfetto 入口

报告离线读取已有 `.pftrace`，无需连接设备、root 或重新采集。适用于原生导出、JSONL 转换以及与系统 trace 合并后的 Anettrace 轨迹，包括 `--trace-tags`。

## 获取与运行

下载 Release 的 `host-tools.tar.bz2` 并解压，在解压目录中运行；源码仓库的用法相同：

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements-perfetto.txt
.venv/bin/python tools/network_report.py analyze capture.pftrace --out report --serve --open
```

生成 `report/report.html` 和 `report/report.json`，启动仅监听 `127.0.0.1` 的临时服务，并打开报告。关闭终端或按 Ctrl-C 停止服务。首次分析时 Perfetto Python 库可能下载 Trace Processor；离线环境可以指定已有二进制：

```sh
.venv/bin/python tools/network_report.py analyze capture.pftrace --out report \
  --trace-processor /path/to/trace_processor_shell --limit 100
```

默认显示最慢的 50 个完整调用、最多 50 个排除调用，`--limit` 范围为 1–1000；总数和连接统计始终覆盖全部观测。报告中的定位 SQL 可查询未列出的原始事件。没有 Anettrace 事件或输入解析失败时返回非零状态。

稍后继续排障，不必重新分析：

```sh
python3 tools/network_report.py serve report --open
# 原文件移动后，必须提供内容完全一致的文件：
python3 tools/network_report.py serve report --trace /new/path/capture.pftrace --open
```

仅阅读报告可直接打开 HTML。完整 Perfetto 入口需要上述本地服务以及访问 `ui.perfetto.dev` 的网络；复制 SQL 后也能手动打开原始 trace 并查询。服务和浏览器均检查 SHA-256，防止报告和轨迹错配。在同一目录重新生成报告后，需要重启已有的本地服务。

## 报告内容和统计口径

| 内容 | 口径 | 如何使用 |
| --- | --- | --- |
| 采集质量 | trace_end 中的 BPF 丢事件、解析/时钟 stats、缓冲压力元数据、未关联事件和调度覆盖提示 | 先确认哪些观测存在缺口；缺失计数显示“未知”，不当作零 |
| 连接概览 | 显式 flow_id；无 flow 时退回显式 socket_id，保留局部观测标记 | 从端点、flow、socket 筛选目标，查询关联的原始记录，包括 socket allocation |
| 慢调用 | `anettrace.syscall`，完整且起点未裁剪，按持续时间降序 | 查看应用调用、返回值、线程、call/socket/flow ID；失败调用也保留 |
| 调度时间 | 每个排行调用窗口与真实执行线程 `thread_state` 的交集 | 区分 Running、R/R+ 可运行等待、其他已观测状态和未覆盖区间 |

连接概览不把共享 socket 的多个 flow 合并为一个连接，也不靠端点相同或时间接近补关联。没有生命周期记录时，连接开始、结束和总生命周期保持未知；这适用于极简 tag 模式和中途开始的采集。

packet 统计只使用 `anettrace.packet` / `anettrace.packet.drop`，排除 socket overview 镜像。事件数包含同一 skb 在多个探针的观测，skb 数按有效 packet_id 去重，均不等同于线上包数。`PERF_RECORD_LOST` / BPF lost_events 是采集事件丢失，不是网络丢包。

应用返回字节仅统计完整、未裁剪且 `result_unit=bytes` 的非负返回值，按 send/write 与 recv/read 分为 TX/RX。批量 sendmmsg/recvmmsg 的 messages 单独计数，不换算字节；未知单位不假定为字节。不再叠加 TCP/UDP 协议层 I/O 或 syscall.complete，避免重复。

调度按 thread track（或其父轨道）解析 utid，校验线程和进程身份及生命周期；不能确定时保留未覆盖。其他状态包含睡眠等状态，不能解释成网络等待。没有 sched 数据的原生 trace 仍可看连接和调用耗时；需要调度分解时，使用与系统调度数据合并后的 trace。报告不推断耗时异常、网络 RTT 或因果链。

## 从结果回到原始事件

每个结果旁有“在 Perfetto 定位”“复制 SQL”和可展开的 SQL / 纳秒时间。点击定位会打开官方 Perfetto UI，在浏览器中载入本地原始 trace，执行该结果的查询；点击查询结果的 ID 箭头可定位原始事件。调度行默认定位原始调用，“查看原始线程状态”另外查询对应的 thread_state；Perfetto 当前需要在结果的 `Interpret id as` 中选择 `thread_state.id`，再点击 ID 箭头定位状态。连接行查询该 ID 的关联事件，质量项查询元数据或 stats。

SQL 使用精确时间、类别及显式关联 ID，避免依赖不同 Trace Processor 版本之间可能变化的 slice ID。JSON 的 `ts_ns` / `dur_ns` 用十进制字符串保存，避免浏览器丢失 64 位时间精度；显示的毫秒值只用于阅读。

本地服务只暴露固定的报告和原 trace 路由，不开放目录，也不允许跨站读取。原 trace 通过 [Perfetto postMessage 接口](https://perfetto.dev/docs/visualization/embedding-api-reference) 传给浏览器中的 UI，不生成公开 trace URL。HTML/JSON 包含事件信息、本机输入路径和定位 SQL，应按原轨迹的敏感程度保存和分享。JSON 格式见 `schemas/network-performance-v1.schema.json`。
