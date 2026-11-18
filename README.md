# fanotify

fanotify 权限事件应答、订阅吊销与重启排水。

所有状态均保存在调用方指定的临时目录，运行只依赖 Python 标准库。

复现：`python -m fanotify repro`。
