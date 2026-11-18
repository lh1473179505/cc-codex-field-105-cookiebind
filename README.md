# devicecode: 设备授权码跨端确认

一个仅使用 Python 标准库的持久化业务服务。在线命令、独立诊断和日志恢复共享同一份状态机。

## 运行

```console
python -m devicecode demo --work ./var
python -m devicecode audit --state ./var/state.json
python -m devicecode recover --journal ./var/journal.jsonl --state ./var/restored.json
python -m unittest discover -s tests -v
```

`repro` 是故障调查入口；它围绕“设备授权码跨端确认”把跨阶段接管、权限吊销、
只读诊断和恢复重放放进同一条场景，输出各项不变量的结论以及在线与离线入口的
digest 对照，命令本身正常结束（退出码为 0），不再并列期望与观察值：

```console
python -m devicecode repro
```

该入口现在覆盖的不变量包括：迁移后来源与目标的进行中事务、可变载荷和游标互不
别名；跨会话提交被拒绝；权限纪元提升后旧纪元已开始的事务可按固定快照收尾而旧
会话无法发起新事务；诊断读取不改动持久化字节；在线状态与日志重放得到的离线
状态结论一致。业务目标和兼容边界见 `docs/`。
