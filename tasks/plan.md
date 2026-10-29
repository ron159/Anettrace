# 通用收发性能报告

## 独立分析 Skill（2026-10-29）

用户要求分析与采集解耦。本次不改采集端 VERSION、不创建 v* 标签、不发布新设备端二进制。

1. 补齐 UID / PID / TID、flow、socket、协议、端点、调用耗时和时间窗口筛选；筛选先于排行截断，质量保持全轨迹口径，明确筛选后计数及未知身份。
2. 将分析脚本、HTML、schema、依赖和流程说明归入自包含的 skills/anettrace-analysis；保留旧 Python CLI 兼容入口。Skill 单独复制到仓库之外仍能生成、验证和查看报告。
3. 先 inspect 可用 UID/flow/socket，再按用户范围生成报告、验证证据、输出报告路径及范围/质量/局限。关联只使用显式身份、实际线程归属和有效 ID，不推断流或 socket 因果。
4. 独立 Python/浏览器/Skill 检查工作流；未来 Skill / 报告改动跳过 C/Android 构建。首次流水线迁移仍验证已有打包兼容。
5. 完成隔离目录实际调用、真实轨迹、多 UID/flow 回归、浏览器过滤、Skill 校验和仓库提交推送。以仓库 Skill 为后续迭代入口，不依赖设备端 Release。

## 时间显示（2026-10-29）

1. 通过 Trace Processor 的时钟映射获取真实 UTC 时间；缺失映射时只展示相对 trace 起点的时间，不用开机时钟或文件时间伪造日期。
2. 页面默认 UTC+8 时分秒与相对时间，支持纯相对时间；创建、SYN/FIN 和证据详情统一格式化，耗时使用 ms / s。
3. 原始纳秒字符串和 Perfetto 深链接保持精确，验证日期跨日、超过 JS 安全整数范围及无时钟快照的轨迹。

## 报告交互与 Socket 时间线（2026-10-29）

1. 验证 Perfetto 官方深链接；用户确认优先自动选中 tag，允许复用同一标签页重新载入。单事件按唯一 ts/dur 定位，集合及重叠事件保留精确 SQL。
2. 从规范 socket allocation 和 TCP packet 标志提取全部 Socket 创建、SYN / SYN-ACK / FIN / RST 观测，保留方向、packet / IP / flow ID 和原始证据；不推断未观测阶段。
3. 五个可访问 Tab（质量、连接、Socket 时间线、慢调用、调度）和 Socket 筛选、分页，避免连续滚动。
4. 真实 Trace Processor 回归、浏览器交互和已采集 trace 验证，更新文档并沿用补丁发布流程。

用户已确认实现范围：离线读取现有 pftrace，展示采集质量、连接概览、慢调用和调度时间，并回到原始证据。

1. 使用现有 Perfetto Python 依赖查询规范事件；排除 socket packet 镜像及 syscall complete 等重复层。
2. 以显式 flow_id / socket_id 汇总连接；完成且未裁剪的系统调用参与耗时排行。批量调用保留 messages 单位。
3. 沿实际 thread track 父子关系确定 utid，计算调用窗口内 Running、Runnable、其他状态和未覆盖时间，缺失数据保持未知。
4. 输出独立可读的 HTML 与结构化 JSON，每项携带稳定定位 SQL、精确纳秒时间和原始证据；提供仅监听回环地址的 Perfetto 打开入口。
5. 使用合成 trace、已有真实 trace、浏览器和发布包验证；按既有流程发布补丁版本。

边界：不推断网络等待或因果链，不将 BPF 丢事件视为丢包，不上传 trace；缺少生命周期或调度数据时明确标记。
