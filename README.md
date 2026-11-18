# jwezip

消息服务分批生成压缩 JWE，内容密钥轮换和中止后标识复用同时发生，旧未压缩消息仍由恢复端接收。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
