# 密钥审计

locations 以十进制序列号字符串为键，环名列表排序无关；operations 保留 id/state/epoch。审计不自动修复双链接。 aborted 操作不得出现在目标环，committed 操作不得仍在源环。
