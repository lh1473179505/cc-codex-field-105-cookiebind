# 会话诊断

第一版表格包含 session、namespace、pid、state、routable。关闭会话仍保留在表中供审计；吊销代数限制新附加，不阻止已绑定会话分离。诊断不得隐式重建路由。
