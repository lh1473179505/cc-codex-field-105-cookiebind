# hkdfkey

支付服务正在轮换 HKDF 主密钥，已受理的派生请求可能跨越轮换边界，失败的轮换也需要能安全重试。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
