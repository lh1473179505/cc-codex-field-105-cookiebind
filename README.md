# cibareq: CIBA 后端认证轮询接管

一个仅使用 Python 标准库的持久化业务服务。在线命令、独立诊断和日志恢复共享同一份状态机。

## 运行

```console
python -m cibareq demo --work ./var
python -m cibareq audit --state ./var/state.json
python -m cibareq recover --journal ./var/journal.jsonl --state ./var/restored.json
python -m unittest discover -s tests -v
```

`repro` 是故障调查入口；它把期望与实际观察并列输出，命令本身正常结束：

```console
python -m cibareq repro
```

近期故障表现为接管后旧流程引用了新事务、权限轮换使进行中的收尾失败，同时诊断调用会改变持久化文件。业务目标和兼容边界见 `docs/`。
