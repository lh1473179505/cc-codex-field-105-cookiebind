# lsmblob

LSM 安全 blob 事务更新、零拷贝视图与失败恢复。

所有状态均保存在调用方指定的临时目录，运行只依赖 Python 标准库。

复现：`python -m lsmblob repro`。
