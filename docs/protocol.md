# 业务状态与事务边界

初始阶段为 `announced`；接管后来源进入 `frontchannel_done`，目标进入 `backchannel_pending`，成功事务结束于 `completed`。允许发起新事务的阶段为 `announced, backchannel_pending`。

浏览器登出通知因网络问题转交后端通道，依赖方授权纪元恰在投递中更新，合规人员导出登出视图并验证中断续跑。

每个事务记录其开始时的权限纪元。吊销阻止旧纪元会话发起新事务，但不 retroactively 取消已经开始且尚未提交的事务。事务只能由所属会话提交，不能仅凭标识符借用另一会话的权限。
