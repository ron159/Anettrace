# 通用收发性能报告

用户已确认实现范围：离线读取现有 pftrace，展示采集质量、连接概览、慢调用和调度时间，并回到原始证据。

1. 使用现有 Perfetto Python 依赖查询规范事件；排除 socket packet 镜像及 syscall complete 等重复层。
2. 以显式 flow_id / socket_id 汇总连接；完成且未裁剪的系统调用参与耗时排行。批量调用保留 messages 单位。
3. 沿实际 thread track 父子关系确定 utid，计算调用窗口内 Running、Runnable、其他状态和未覆盖时间，缺失数据保持未知。
4. 输出独立可读的 HTML 与结构化 JSON，每项携带稳定定位 SQL、精确纳秒时间和原始证据；提供仅监听回环地址的 Perfetto 打开入口。
5. 使用合成 trace、已有真实 trace、浏览器和发布包验证；按既有流程发布补丁版本。

边界：不推断网络等待或因果链，不将 BPF 丢事件视为丢包，不上传 trace；缺少生命周期或调度数据时明确标记。
