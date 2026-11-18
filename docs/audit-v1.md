# 审计兼容

审计项包含 operation、namespace、decision、phase；decision 是操作开始时的完整 ASCII 决策串。审计不释放 memoryview，不更改 phase。 rolled_back 后当前 blob 与进行中视图都应恢复操作前内容。
