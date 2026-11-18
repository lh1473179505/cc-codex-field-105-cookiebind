# pkcs11op

HSM 密钥轮换期间已有签名会话继续执行，机制错误会中止操作并复用业务标识，旧 token 标签还需离线恢复。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
