# tlskeylog

TLS 排障系统在主密钥轮换期间继续完成握手，审计人员会读取已关闭会话的 key log 并导入 TLS 1.2 历史记录。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
