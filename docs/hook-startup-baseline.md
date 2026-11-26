# Hook 启动基线

基线使用正式版 v0.8.18 的 Android arm64 二进制。发布清单的 SHA-256 校验通过，设备端 `--version` 报告提交 `387e8133def3ae096381cbc3f650700f774a92d1`。测试设备为 PKC130，内核版本为 `6.6.118-android15-8`。

```sh
./anettrace --capture-trace --duration 5 --output /data/local/tmp/hook-startup.pftrace --force --debug
```

每轮由主机记录 ADB 日志到达时间，收到 `begin trace...` 后再启动两轮 TCP 和 UDP 回环交换。三个 trace 均生成成功，负载程序校验通过，日志未报告采集丢失。

| 阶段 | 第 1 轮 | 第 2 轮 | 第 3 轮 | 中位数 |
| --- | ---: | ---: | ---: | ---: |
| 符号解析 | 856 ms | 898 ms | 934 ms | 898 ms |
| 骨架打开后至开始挂载 | 2,086 ms | 2,071 ms | 2,069 ms | 2,071 ms |
| 挂载 | 146 ms | 154 ms | 141 ms | 146 ms |
| 启动至采集就绪 | 3,249 ms | 3,311 ms | 3,324 ms | 3,311 ms |

新版 `--debug` 中的 `trace startup` 使用设备的单调时钟。相邻 `prepare_begin` / `prepare_end`、`symbols_begin` / `symbols_end`、`load_begin` / `load_end`、`load_end` / `attach_end` 的差值分别给出准备、解析、加载和挂载耗时。`ready` 表示采集缓冲区已就绪，`first_sample` 表示 poll 收到首条 BPF 样本，两者的间隔包含等待负载的时间。原始统计轮询路径提供 `ready`，事件轮询路径在收到样本时才会输出 `first_sample`。

此基线覆盖一台 Android 6.6 设备的短时回环负载。5.10/5.15、每个程序的 verifier 指令数及运行成本、整机 syscall 开销和吞吐压力测试仍待测量。
