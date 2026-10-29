# 独立分析 Skill

采集器负责记录事件；[anettrace-analysis](../skills/anettrace-analysis/SKILL.md) 负责分析已有 `.pftrace`。Skill 自带 Python 脚本、HTML、schema、依赖和分析流程，整目录安装后可脱离源码仓库运行，无需设备、adb、root 或重新编译 Anettrace。

## 交给 AI 使用

让支持 Skills 的 AI 安装仓库的 `skills/anettrace-analysis` 目录（分支为 `master`）。例如对 Codex 说：

> 使用 skill-installer，从 https://github.com/ron159/Anettrace/tree/master/skills/anettrace-analysis 安装这个 Skill。

安装后可以这样提问：

> 使用 $anettrace-analysis 分析 /path/capture.pftrace。先列出 UID 和 flow，再筛选 UID 10187、TCP、端口 443、耗时至少 5ms 的调用，生成报告到 /path/report，并说明调度覆盖和原始证据。

> 使用 $anettrace-analysis，只看 flow tcp-1，梳理 socket 创建、SYN/FIN、调用耗时和返回量，保留 packet / socket / IP ID 及 Perfetto 定位入口。

未安装时也可让 AI 直接读取本仓库的 `skills/anettrace-analysis/SKILL.md` 执行。AI 会先检查真实候选项，按范围生成报告，再校验 JSON、HTML 和 trace 指纹；不因缺字段猜测身份或根因。

## 手动运行

Python 3.10+，依赖沿用现有 Perfetto / jsonschema。虚拟环境放在工作目录，Skill 可放在任意位置：

```sh
python3 -m venv .venv
.venv/bin/pip install -r skills/anettrace-analysis/requirements.txt
.venv/bin/python skills/anettrace-analysis/scripts/network_report.py inspect capture.pftrace
.venv/bin/python skills/anettrace-analysis/scripts/network_report.py analyze capture.pftrace \
  --uid 10187 --uid 10188 --protocol tcp --endpoint-port 443 \
  --min-call-ms 5 --out report --serve --open
.venv/bin/python skills/anettrace-analysis/scripts/network_report.py validate report
```

首次运行可能下载 Trace Processor，离线环境给 inspect / analyze / serve 加 `--trace-processor /path/trace_processor_shell`。仅查看已有报告时直接打开 HTML；交互筛选或 Perfetto 入口需运行 `serve report --open`。

## 更新与兼容

- 分析的唯一实现位于 `skills/anettrace-analysis/`。修改脚本、模板、schema 或流程说明并更新安装副本即可；已生成的报告需要重新生成或重启服务后重新筛选。
- 仓库用法通过 `git pull` 更新。全局安装的 Skill 不会自动跟随仓库更新，需要用安装工具更新其副本；不必更新设备上的 Anettrace。
- `tools/network_report.py` 保留兼容入口，转发到 Skill 实现；后续 host-tools 包仍携带 Skill，但获取最新分析能力无需等待 host-tools Release。
- 独立 `Analysis Skill` CI 验证真实 Trace Processor、仓库外安装副本和旧入口。仅分析目录、报告测试和文档的修改跳过 C / Android 构建，不改采集端 VERSION，不创建 v* 标签。
- 现有 trace 缺少 UID、owner 或生命周期事件时，升级分析脚本不能补出未采集数据。`unknown` 是可筛选的结果，不代表 UID 0。

详细口径见 [分析流程](../skills/anettrace-analysis/references/analysis-workflow.md)，报告界面及 Perfetto 操作见 [收发性能报告](network-performance-report.md)。
