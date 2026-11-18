# 快照兼容

watches 项保留 wd/path/state，pending 是待投递事件的只读视图，dropped 是累计溢出数。快照不得清空队列或重置 dropped。 revoked watch 的已排队事件仍可被审计，但新事件不得发布。
