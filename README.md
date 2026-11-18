# sysctlsec

安全 sysctl 的运行态/持久态事务、命名空间迁移和恢复。

所有状态均保存在调用方指定的临时目录，运行只依赖 Python 标准库。

复现：`python -m sysctlsec repro`。
