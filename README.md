# minisign

制品发布切换签名密钥时，已加载制品仍等待签名，双通道发布中的第二个失败可能留下首个签名。

运行 `python -m unittest discover -s tests -v` 可观察当前跨阶段故障。
