# 第一版诊断输出

输出顶层为 settings/pending，每个设置保留 key、namespace、runtime、persistent、consistent。诊断不创建意图，也不自动修复漂移。迁移期间，原命名空间的消费者仍要能解释最后一条完整记录。
