# hpkebind

收件系统升级 HPKE 接收密钥时，批量封装与交互封装会并存，超限消息还可能在最后阶段失败。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
