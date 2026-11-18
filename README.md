# xmlenc

XML 网关同时处理整文档与流式分片，加密密钥切换后旧文档仍要完成提交，超限分片批也需要回滚。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
