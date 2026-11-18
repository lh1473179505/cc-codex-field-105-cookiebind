# 监控兼容

events 中保留 name、running、cpus、cgroup。running 只在 armed 时为真，cancelled/closed 均不得显示运行；计数器每 CPU 非负。监控不确认恢复意图，也不消费取消记录。
