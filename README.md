# spnegox: SPNEGO 机制协商交接

一个仅使用 Python 标准库的持久化业务服务。在线命令、独立诊断和日志恢复共享同一份状态机。

## 运行

```console
python -m spnegox demo --work ./var
python -m spnegox audit --state ./var/state.json
python -m spnegox recover --journal ./var/journal.jsonl --state ./var/restored.json
python -m unittest discover -s tests -v
```

`repro` 是故障调查入口；它把跨阶段接管、权限吊销、只读诊断和恢复重放放进同一组回归，
直接给出业务结论（`status: ok`）以及在线与离线入口的一致性摘要，命令本身正常结束：

```console
python -m spnegox repro
```

回归覆盖的业务约束：迁移后来源与目标的进行中事务、可变载荷和游标互不别名；跨会话提交被拒绝；
权限纪元提升后旧纪元已开始的待提交事务按固定快照收尾、旧会话不能发起新事务；
诊断只读且重复读取结果一致；恢复按日志实际顺序重放，在线与离线入口结论一致。业务目标和兼容边界见 `docs/`。
