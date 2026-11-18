# 诊断兼容

报告必须保留原路径键、namespace、mask 和 alice_effective 字段，且只读。恢复过程可追加事件，但不能把 rolled_back 改成 committed；旧脚本根据该状态决定是否告警。
