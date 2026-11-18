# 用量诊断

旧监控读取 used_bytes、limit_bytes、reservations 和 states。used_bytes 是非负已预留总量，等于 reservations 数值之和；诊断只读，不能替清理器确认完成。
