# 上游合入评估

本次结论：**有选择性移植的价值，当前不建议整体合并上游 `master`**。
本次完成源码与提交历史评估，未导入上游代码；下列待移植项不属于已发布修复。

## 比较范围

- 检查日期：2026-10-29。
- Anettrace 基线：[`00cb511`](https://github.com/ron159/Anettrace/commit/00cb511b95f9a40c6bea139f7a32989d53c3033c)，v0.8.12。
- 上游：[`OpenCloudOS/nettrace master @ fcfa072`](https://github.com/OpenCloudOS/nettrace/commit/fcfa07232026025388fa58d8b77d68f867fcd152)，提交日期 2026-03-05。
- 共同祖先：`a9f133477b02728e2430f7db9249d556b7162b84`。
- 两侧各有 126 / 30 个独有提交；上游 30 个中，22 个为非 merge 提交。

以上是固定提交之间的快照，不表示未来上游不会变化。复查时先更新远程引用：

```sh
git fetch --prune upstream
git merge-base HEAD upstream/master
git rev-list --left-right --count HEAD...upstream/master
git log --reverse --no-merges --oneline HEAD..upstream/master
```

提交不在祖先链中，不等于修复缺失。`git cherry` 的补丁匹配也不能替代源码语义比较。

## 已有对应实现

| 上游提交 | 当前证据 | 处理意见 |
| --- | --- | --- |
| [`1e111a6`](https://github.com/OpenCloudOS/nettrace/commit/1e111a64dfe36a34ed6ef973e0bf92db796b8f10)：iptables 表名读取 | 本分支 `2a5c46c`；`src/progs/core.c` 已直接读取到事件表名缓冲，`skb_parse.h` 的 `_L` 使用目标大小 | 无需重复移植 |
| [`b8b00e1`](https://github.com/OpenCloudOS/nettrace/commit/b8b00e13db192381a80befd89d5c92bf95bfbacb)：符号查询缓存 | 本分支 `800a292`；`utils/parse_sym.c` 已复用 kallsyms 数据、保留缓存并按行解析符号 | 无需重复移植 |
| [`3fe94f9`](https://github.com/OpenCloudOS/nettrace/commit/3fe94f93ed7033d8ea2ffa5f31fa212fa4afe9c6)：新内核 timer 字段保护 | 本分支 `3a78e2a`；`probe_parse_sk()` 已分别检查两个字段，均不存在时写入 0 | 无需重复移植 |
| [`f5c46e7`](https://github.com/OpenCloudOS/nettrace/commit/f5c46e744a0581b00ec0490310737d283b20177d)：编译告警整理 | `src/progs/skb_macro.h` 已分别保护 `likely` / `unlikely`；`_(src)` 的括号整理仍有文本差异 | 不作为合并驱动因素 |

## 值得单独移植或验证

| 上游提交 | 本分支现状 | 优先级与验证要求 |
| --- | --- | --- |
| [`8f771ea`](https://github.com/OpenCloudOS/nettrace/commit/8f771eaa5bd5c9f6678302b58a3fdfd9cb153f55)：tracefs 路径发现 | `src/trace.c`、`dropreason.c`、`rstreason.c` 仍硬编码 `/sys/kernel/debug/tracing`；`debugfs_mounted()` 只检查 debugfs 挂载 | 优先单独适配。仅挂载 `/sys/kernel/tracing` 的系统存在兼容缺口；同时检查 `utils/bpf_utils.c` 的兼容 kprobe 路径，覆盖两类挂载及目录缺失场景 |
| [`fb45838`](https://github.com/OpenCloudOS/nettrace/commit/fb45838283b46f0f96b9bec65095222e9524f59c)：latency 上下文与收尾 | 本分支仍保留旧 `pre_handle_latency()`，但 `handle_entry_finish()` 已有本项目新增的 skb 生命周期处理 | 先在运行内核复现和添加回归，再按双后端适配；覆盖带过滤 / 无过滤、summary、free、计数与上下文清理 |
| [`bedeccb`](https://github.com/OpenCloudOS/nettrace/commit/bedeccbfb059b01f824008743253fbd2581f164e)：monitor 过滤 | `handle_entry()` 仍使用 `filter = !info->matched`，与上游显式判断 context mode 的实现不同 | 与上下文收尾一起验证，覆盖 monitor 的地址、线程与 UID 隔离；不能靠这一行差异宣称已复现漏过滤 |
| [`b7c5cb0`](https://github.com/OpenCloudOS/nettrace/commit/b7c5cb0cf1939d8305e15d77749c15cee4c054e6)：tiny 输出 | 本分支已有 `args->tiny_output` 判断，但 `pre_tiny_output()` 和上游重构后的入口 / 返回路径不同 | 依赖前述上下文重构，验证 entry / return、克隆、free 与事件计数后再移植 |

这里确认的是源码覆盖和兼容性缺口；本次没有在仅挂载 tracefs 的 Linux 或旧内核上复现，
也没有把 latency、monitor、tiny 的代码差异当作已验证的运行缺陷。

## 不整体同步的原因

- 上游当前树已删除 `src/trace_tracing.c`、`src/progs/tracing.c`、`feat_args_ext.c`，并把公共 BPF 核心并入 kprobe。Anettrace 的构建和运行仍依赖这些 TRACING / KPROBE 双后端能力，直接同步会影响现有采集链路。
- 上游 [`c9dc89d`](https://github.com/OpenCloudOS/nettrace/commit/c9dc89da7a9779f9fdd368ef6d1696561b1235df) 移除了 monitor；本项目仍公开支持该模式。
- 上游 [`f65f176`](https://github.com/OpenCloudOS/nettrace/commit/f65f176268f8499c21a533b912d279f9627c3b34) 改为默认动态链接；本项目 Android arm64 发布依赖静态二进制及下载后的静态链接校验。Linux 打包可另行评估。
- 上游 selftests 系列可借鉴模式覆盖，但应适配 Anettrace 名称、双后端、过滤与现有 CI；不能替代本项目的设备端、流量、唤醒及 Perfetto 集成测试。
- 其余颜色 / 调试日志、RPM / Arch 打包、shell 补全、分支说明、删除旧 README，以及 3.x 构建包含顺序等改动，应按各自需求处理；它们不构成整体合并的理由，也不代表本项目已验证 3.x 内核兼容性。

后续建议先处理 tracefs 路径兼容，再用可复现用例决定是否移植模式修复。
每项独立提交并验证 Linux / Android CI；涉及 BPF 或挂载路径时补充对应环境的运行验证。
