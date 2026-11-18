# 业务状态与事务边界

初始阶段为 `offered`；接管后来源进入 `selected`，目标进入 `delegated`，成功事务结束于 `established`。允许发起新事务的阶段为 `offered, delegated, selected`。

SPNEGO 初始上下文交給 Kerberos 机制继续建立，领域票据授权版本中途撤销，诊断工具读取协商轨迹并测试节点恢复。

每个事务记录其开始时的权限纪元。吊销阻止旧纪元会话发起新事务，但不 retroactively 取消已经开始且尚未提交的事务。事务只能由所属会话提交，不能仅凭标识符借用另一会话的权限。
