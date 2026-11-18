# parbind: PAR 授权句柄迁移

一个仅使用 Python 标准库的持久化业务服务。在线命令、独立诊断和日志恢复共享同一份状态机。

## 运行

```console
python -m parbind demo --work ./var
python -m parbind audit --state ./var/state.json
python -m parbind recover --journal ./var/journal.jsonl --state ./var/restored.json
python -m unittest discover -s tests -v
```

`repro` 是回归调查入口；它以不变量断言串联跨阶段接管、权限轮换、只读诊断和日志
重放，全部通过时输出 `status: ok` 与在线/离线一致的摘要，不再并列期望与观察值：

```console
python -m parbind repro
```

近期故障表现为接管后旧流程引用了新事务、权限轮换使进行中的收尾失败，同时诊断调用会改变持久化文件。业务目标和兼容边界见 `docs/`。
