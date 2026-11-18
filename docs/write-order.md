# 写入与恢复

配置变更跨运行态和持久态两个阶段。恢复器只处理有完整意图且停在 runtime_written 的记录；没有意图的写入必须可被启动核验发现并回退。同一 token 的恢复沿用开始时的纪元，不能重新申请权限。

## 写前意图（write-ahead intent）

1. `proposed`：记录意图（token、目标值、`before_runtime`、`before_persistent`、
   `epoch`）并原子落盘，此步先于任何运行态修改。
2. `runtime_written`：运行态生效后再次原子落盘；此时断电也始终有可核验的先前值。
3. `durable_written` → `committed`：持久态写入与提交状态在同一次落盘中完成。

每次运行态变化都能在 `intents` 中找到带先前值与原始纪元的归属记录，不存在无主的
提前生效。

## 启动恢复

- `proposed`：运行态尚未生效，回滚持久态先前值并标记 `aborted`。
- `runtime_written`：按 `before_runtime` 回滚运行态并标记 `aborted`。
- `durable_written`：补齐持久态目标值并标记 `committed`。
- 其后扫描仍与持久态不一致且没有开放意图认领的运行态值，一律回退到持久态值。

恢复只读取意图中保存的 `epoch`，不推进全局 `epoch`，也不要求 token 重新进入
`active`。`committed` 与 `aborted` 为终态，重复恢复保持幂等。
