# 数据流与统计口径

## 脚本分工

| 组件 | 输入 → 输出 | 责任 |
| --- | --- | --- |
| 设备端 Anettrace（仓库 src/） | 内核观测 → JSONL / pftrace | 抓包、唤醒和收发事件采集；本 Skill 不编译或运行它 |
| 仓库 tools/anettrace_to_perfetto.py | JSONL → pftrace | 离线格式转换，保留源时钟及关联 ID |
| 仓库 tools/merge_trace_with_anettrace.py | 网络数据 + 系统 trace → pftrace | 时钟对齐和合并；已有 pftrace 无需重复转换 |
| 本 Skill scripts/network_report.py | pftrace → 清单 / HTML / JSON | inspect、筛选、统计、证据、验证和本地查看 |
| 仓库 tools/perfetto_sql/ | 已载入 trace → SQL 结果 | 可选专题查询，不是通用报告运行依赖 |
| 仓库 diagnose/validate/soak_android_connect.py | 设备连接探测 → 专项报告 | 主动建连实验，与本 Skill 的已有轨迹分析分开 |

输入必须包含 Anettrace 事件。只有系统调度数据时不能推断 UID、网络调用或包因果；JSONL 需先使用仓库转换工具生成 pftrace。这些转换/采集工具不是本 Skill 的运行依赖。

## 工作流

1. 保留原 trace；inspect 确认 SHA-256、质量、可选身份和显式 ID。
2. 根据用户问题选择条件。生成输出目录中的报告；不要覆盖输入 trace。
3. 从 scope 验证实际过滤结果，从 calls 确认排行截断，再看每个 UID / 流的完整调用耗时、返回量和调度。
4. 验证报告 JSON、HTML 和 trace 身份一致；关键结论逐项回到 evidence。
5. 需要继续钻取时用 serve 的交互筛选，或用新的 CLI 条件生成另一份报告。数据缺失时说明局限，不以额外抓包或设备操作替代当前授权。

## 身份与关联

- syscall 的 uid 是调用者；socket allocation 的 uid 是创建上下文。缺失时只可从实际 thread track 的进程 UID 补全，并检查 TID、PID 和生命周期一致。
- packet / flow 使用明确的 socket owner_uid / owner_tgid / owner_tid；packet.uid 是执行上下文，不能当作应用身份。owner_valid=false/0 或所有者 PID 未知时保持未知。UID 0 在明确身份下是有效 root UID。
- app_uid / app_pid / app_tid 供筛选使用，identity_source 保留 event / thread_process / socket_owner / unknown；原始 uid 和 owner_* 不覆盖。
- 协议、地址、端口可沿显式 flow_id 使用该流的观测值。缺少 flow_id 时，仅在同一 socket 的协议唯一时补充协议筛选，不跨共享 UDP socket 借目的地址。不是按 tuple 或时间近似补关联。
- 同类值 OR，不同字段 AND。地址和端口各指流任一端的观测值，不隐含二者必须属于同一端。

## 条件

| CLI | 含义 |
| --- | --- |
| --uid / --pid / --tid（可重复） | 应用或已知 socket 所有者身份；unknown 可选未知身份 |
| --flow / --flow-id（可重复） | 完整 flow_id 或 flow_tag，精确匹配 |
| --socket / --socket-id（可重复） | 显式 socket_id / owner_socket_id |
| --protocol（可重复） | tcp、udp、icmp、icmpv6 或 unknown |
| --address / --endpoint-port（可重复） | 任一端 IP / 端口；IPv6 会规范化，不做 DNS 查询；--port 仍是本地服务监听端口 |
| --syscall（可重复） | 精确调用名，如 recvmsg、sendto、write |
| --min-call-ms / --max-call-ms | 仅完整、未裁剪调用的耗时范围，包含上下界 |
| --start-ms / --end-ms | 相对整个 trace 起点的窗口，左闭右开；调用按相交选择，不裁剪其耗时和调度窗口 |
| --limit | 最多列出的调用 / 排除调用数，1–1000；匹配总数仍完整统计 |

调用名或耗时条件会把非调用观测收缩到命中调用的显式 flow；没有 flow 时才使用其 socket。关联观测不是“该次调用产生的包”的因果证明。匹配 socket 的创建记录作为 context_only 额外保留，不计入匹配事件统计，连接计数也不额外制造一条创建连接。

## 事件与指标

- 应用调用只统计 anettrace.syscall。完成且未裁剪、具有 result 的调用进入排行；失败调用保留。incomplete / start_clipped / 缺结果单独展示。
- canonical packet 是 anettrace.packet 和 anettrace.packet.drop；排除 anettrace.socket.packet 镜像。packet_events 是探针观测次数；observed_skbs 按有效 packet_id 去重，都不是线上包数。
- connection.key 优先 flow_id，缺失时退回 socket_id。共享 socket 的多个 flow 不合并。call_time 的 p50 / p95 使用完整调用耗时的最近秩（ceil(p*N)）分位数；不完整调用不当成 0。
- 应用返回量按 bytes / messages 分开；不累加协议 I/O 与 syscall.complete 的镜像值。
- 调度是完整调用窗口与真实线程 thread_state 的交集；校验线程和进程身份、生命周期，不能借 socket owner 或相近 TID 的状态。Running、R/R+、其他状态、未覆盖分别保留。
- BPF lost_events 是采集丢记录，不是网络丢包。缺少 trace_end 时计数未知；通知值不与累计值相加。采集质量始终是整个原 trace 的口径。
- 创建来自 socket allocation；SYN=2、ACK=16、FIN=1、RST=4。保留每次探针观测和重传，不推断四次挥手完成或未记录的销毁。

## 时间、证据与边界

显示默认 UTC+8 时分秒 + 相对 trace_bounds 起点的 ms/s，跨日补日期。使用 TO_REALTIME 对每个时刻转换，缺少映射时保持未知；耗时与相对偏移不加时区。JSON 的 ts_ns / dur_ns 和 realtime_by_ts 保留十进制字符串，不能先转 JS Number 再做时间差。

单个事件的 evidence.sql 按精确 ts/dur/category/name/显式 ID 查找。slice ID 随 Trace Processor 版本可能改变，不能作为长期唯一键。ts/dur 在全 trace 唯一时才使用 Perfetto 自动选中；否则运行精确 SQL，点击结果 ID 箭头。连接查询含完整流上下文，质量查询覆盖原 trace，均可能超出当前筛选统计。

已有 trace 缺字段时，更新 Skill 能改善筛选与呈现，但不能补出未采集的数据。保留 unknown；不要把 Other 当网络等待，把重传探针重复当多个线上包，把时间先后当唤醒或收发因果。
