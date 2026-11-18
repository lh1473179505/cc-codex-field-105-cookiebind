# 审计流

decisions 项保留 event、decision、epoch，decision 只允许 allow/deny；events 保留 id、path、state。审计读取不推进事件状态。同一事件至多产生一个最终决定，迟到应答不能生成第二条。
