# 通用收发性能报告与 Perfetto 入口

报告离线读取已有 `.pftrace`，无需连接设备、root 或重新采集。适用于原生导出、JSONL 转换以及与系统 trace 合并后的 Anettrace 轨迹，包括 `--trace-tags`。

## 获取与运行

推荐使用独立 [anettrace-analysis Skill](analysis-skill.md)，AI 可按流程生成、筛选和验证报告。整个 `skills/anettrace-analysis` 可单独安装，不依赖设备端 Release。源码仓库或后续 host-tools 包仍保留旧命令兼容入口：

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

默认显示最慢的 50 个完整调用、最多 50 个排除调用，`--limit` 范围为 1–1000；调用总数和连接统计覆盖所有匹配观测，筛选发生在排行截断前。报告中的定位 SQL 可查询未列出的原始事件。没有 Anettrace 事件或输入解析失败时返回非零状态。

先列候选项，再组合筛选：

```sh
.venv/bin/python tools/network_report.py inspect capture.pftrace
.venv/bin/python tools/network_report.py analyze capture.pftrace --out report \
  --uid 10187 --uid 10188 --protocol tcp --endpoint-port 443 --min-call-ms 5
.venv/bin/python tools/network_report.py analyze capture.pftrace --out report-flow \
  --flow tcp-1 --syscall recvmsg --start-ms 100 --end-ms 3000
.venv/bin/python tools/network_report.py validate report
```

支持 UID、PID、TID、完整 flow_id / flow_tag、socket_id、协议、任一端 IP / 端口、调用名、最小/最大调用耗时及相对时间窗口。同一字段多个值取 OR，不同字段取 AND；用 `unknown` 可选缺失字段。`--port` 是本地服务端口，端点筛选使用 `--endpoint-port`。时间窗口按调用相交选择，耗时和调度仍保留完整调用窗口。

页面顶部展开筛选面板可交互调整条件，候选提示包含原 trace 中的事件数和调用数。应用后服务重新计算完整候选和调度，更新 JSON / HTML；清空条件可恢复全轨迹。采集丢事件、packet 和调用质量计数始终按原轨迹统计，调度覆盖提示针对当前排行。每个流增加完整调用数、最大耗时和 P95；JSON 另含总耗时、最小耗时及 P50。

应用 UID 优先使用调用者身份；packet / flow 仅使用有效的 socket owner 身份。packet 执行上下文 UID 不作为应用身份，缺失值不猜测。匹配 socket 的创建记录作为上下文保留，即使早于时间窗或创建者 UID 不同，也会标注 `context_only`。统计范围见 `scope`，候选项见 `inventory`；详细规则见 [分析流程](../skills/anettrace-analysis/references/analysis-workflow.md)。

页面按“采集质量 / 连接概览 / Socket 时间线 / 慢调用排行 / 调度时间”五个 Tab 切换。表格分页，切换 Tab 不重新分析；可用左右方向键、Home / End 切换，URL 的页面片段可保存当前 Tab。

时间默认按 UTC+8 显示时分秒（微秒精度），下方同时显示距 trace 起点的 `+123.456 ms` / `+1.234567 s`；也可在顶部切换为纯相对时间。顶部给出起点的完整日期，跨日事件另外显示日期。相对时间以整个 trace 的起点为零点，不受筛选或时区影响；耗时本身不加时区。

UTC+8 使用 Trace Processor 的 `TO_REALTIME` 对各个显示时刻分别转换，不把开机时间、文件修改时间当作 UTC；缺少墙钟映射时明确回退相对时间。原始纳秒字符串仍保存在 JSON 和定位 SQL 中，Perfetto 跳转精度不变。

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
| Socket 时间线 | 显式 socket_id（缺失时使用 owner_socket_id）的 allocation 和 TCP 标志观测 | 查看全部或按 Socket ID 筛选创建、SYN、SYN-ACK、FIN、RST，定位每条原始 tag |
| 慢调用 | `anettrace.syscall`，完整且起点未裁剪，按持续时间降序 | 查看应用调用、返回值、线程、call/socket/flow ID；失败调用也保留 |
| 调度时间 | 每个排行调用窗口与真实执行线程 `thread_state` 的交集 | 区分 Running、R/R+ 可运行等待、其他已观测状态和未覆盖区间 |

连接概览不把共享 socket 的多个 flow 合并为一个连接，也不靠端点相同或时间接近补关联。没有生命周期记录时，连接开始、结束和总生命周期保持未知；这适用于极简 tag 模式和中途开始的采集。

Socket 时间线的概览列出每个 socket 的创建开始、首个 SYN、SYN-ACK、FIN 和 RST 的时刻，遵循顶部选择的时间显示方式。输入完整或部分 Socket ID 可筛选，点击概览中的 ID 可查看该 socket；清空输入或点击“查看全部”恢复全部 socket。事件类型可进一步筛选。

明细不受 `--limit` 限制，保留每次探针观测和重传，包括创建 allocation 的开始 / 完成时间、方向、端点、flow_id、packet_id、ip_id、TCP flags / seq / ack。创建只来自 `anettrace.socket` 的 `socket allocation`，TCP 阶段只来自规范 packet/drop 的 `tcp_flags`（SYN=2、ACK=16、FIN=1、RST=4）；排除 socket packet 镜像。未捕获创建、SYN 或 FIN 时显示“未观测”，不拿首包时间代替创建时间。首个 FIN 只是一个关闭方向的观测，不代表四次挥手完成；不据此推断 RTT、完整建连或 socket 销毁时间。

packet 统计只使用 `anettrace.packet` / `anettrace.packet.drop`，排除 socket overview 镜像。事件数包含同一 skb 在多个探针的观测，skb 数按有效 packet_id 去重，均不等同于线上包数。`PERF_RECORD_LOST` / BPF lost_events 是采集事件丢失，不是网络丢包。

应用返回字节仅统计完整、未裁剪且 `result_unit=bytes` 的非负返回值，按 send/write 与 recv/read 分为 TX/RX。批量 sendmmsg/recvmmsg 的 messages 单独计数，不换算字节；未知单位不假定为字节。不再叠加 TCP/UDP 协议层 I/O 或 syscall.complete，避免重复。

调度按 thread track（或其父轨道）解析 utid，校验线程和进程身份及生命周期；不能确定时保留未覆盖。其他状态包含睡眠等状态，不能解释成网络等待。没有 sched 数据的原生 trace 仍可看连接和调用耗时；需要调度分解时，使用与系统调度数据合并后的 trace。报告不推断耗时异常、网络 RTT 或因果链。

## 从结果回到原始事件

每个结果旁有“在 Perfetto 定位”“复制 SQL”和可展开的 SQL / 时间。单条事件使用官方 `ts` / `dur` 深链接自动选中原始 tag，展示选中事件的详情。同一报告页面中首次打开 Perfetto 后，后续点击复用同一浏览器标签页；关闭该标签页后可重新打开。

按当前官方接口限制，深链接选择只在页面首次载入 trace 时生效，因此每次跳转都会在同一标签页重新载入 trace，原有缩放、固定轨道等 UI 状态会重置。报告缓存已经校验的 trace 字节，后续点击不重复从本地服务读取。单纯更新 URL 片段或 postMessage 时间范围不能保证重新选中 tag，所以没有使用该方式冒充精确定位。参见 [Perfetto 深链接](https://perfetto.dev/docs/visualization/deep-linking-to-perfetto-ui) 和 [事件选择实现](https://github.com/google/perfetto/blob/main/ui/src/plugins/dev.perfetto.DeeplinkQuerystring/index.ts)。报告页面刷新后需重新建立定位会话。

如果原 trace 中同一 `ts` / `dur` 有多个事件（包括不同轨道的重叠 tag），官方选择参数不能唯一确定目标，报告会改为运行精确 SQL；点击查询结果的 ID 箭头定位，避免自动选错。汇总项本身包含多条事件，同样使用 SQL 查询。调度行默认定位原始调用，“查看原始线程状态”另外查询对应的 thread_state；Perfetto 当前需要在结果的 `Interpret id as` 中选择 `thread_state.id`，再点击 ID 箭头定位状态。

SQL 使用精确时间、类别及显式关联 ID，避免依赖不同 Trace Processor 版本之间可能变化的 slice ID。JSON 的 `ts_ns` / `dur_ns` 用十进制字符串保存，避免浏览器丢失 64 位时间精度；显示的毫秒值只用于阅读。

本地服务只暴露固定的报告和原 trace 路由，不开放目录，也不允许跨站读取。原 trace 通过 [Perfetto postMessage 接口](https://perfetto.dev/docs/visualization/embedding-api-reference) 传给浏览器中的 UI，不生成公开 trace URL。HTML/JSON 包含事件信息、本机输入路径和定位 SQL，应按原轨迹的敏感程度保存和分享。JSON 格式见 Skill 的 `assets/report.schema.json`；原 `schemas/network-performance-v1.schema.json` 保留兼容约束。
