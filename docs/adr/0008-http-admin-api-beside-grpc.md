# 浏览器走 HTTP Admin API，Node 与 hz 继续用 gRPC

Admin Console 调用 `hz-coord` 上的一层薄 REST/JSON HTTP Admin API（路径大致为 `/admin/api/…`）。实现调用 gRPC Admin RPC 已经在用的同一套 Admin 领域逻辑。Node 与 `hz` 命令行继续使用 gRPC（`hz.v1.Coord`）。不要求浏览器说 gRPC-Web。

v1 经这层 HTTP 开放的运维只有白名单上的两项：触发已有的 SQLite 打包备份，以及读取备份与证书的健康状态。没有任意 shell，v1 也不经此 API 做 systemctl 重启或升级。
