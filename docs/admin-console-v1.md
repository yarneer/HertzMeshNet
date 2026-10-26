# Admin Console v1

给 Admin 用的浏览器界面，嵌在 `hz-coord` 的 `/admin/`。放置见 [ADR-0007](adr/0007-admin-console-in-coord.md)，浏览器与 gRPC 的分工见 [ADR-0008](adr/0008-http-admin-api-beside-grpc.md)。术语 **Admin Console** 以 [GLOSSARY.md](../GLOSSARY.md) 为准。本文只定 v1 范围。

Browser UI for Admins, embedded at `/admin/` on `hz-coord`. Placement: [ADR-0007](adr/0007-admin-console-in-coord.md). HTTP beside gRPC: [ADR-0008](adr/0008-http-admin-api-beside-grpc.md). The term **Admin Console** is defined in [GLOSSARY.md](../GLOSSARY.md). This note records v1 scope only.

认证是 Kanidm OIDC，只有 `hznet_admins` 的成员可以进入。前端是少量静态 HTML/CSS/JS，没有 SPA 构建链。HTTP 处理函数调用 gRPC Admin RPC 已在用的同一套领域逻辑；Node 与 `hz` 仍走 `hz.v1.Coord`。

Auth is Kanidm OIDC, limited to members of `hznet_admins`. The frontend is a little static HTML/CSS/JS, with no SPA build. HTTP handlers call the same Admin domain logic as the gRPC Admin RPCs; nodes and `hz` stay on `hz.v1.Coord`.

## 页面

| 页面 | v1 | 说明 |
|---|---|---|
| Node 列表 | 做 | 列出全部 Node（含已吊销），改名、吊销、删除。权限与现有 gRPC Admin RPC 相同，只给 Admin |
| Auth Key | 做 | 签发与吊销。明文只在签发时显示一次，吊销用当时给出的 Key ID。领域逻辑没有列表接口，v1 不做 Key 清单 |
| Policy | 只读 | 查看当前 Policy。不在浏览器里编辑、推送或回滚 |
| 健康 | 做 | 读取备份新旧与证书状态 |
| 运维 | 白名单 | 只触发已有的 SQLite 打包备份（`scripts/deploy/backup.sh`）。无任意 shell，无 systemctl 重启或升级 |
| 部署向导 | 做 | 按顺序列出下一步并链到 runbook。不执行命令 |
| User 自助 | 不做 | 普通 User 没有页面 |

Pages: Node list (including revoked nodes; rename, revoke, delete — Admin only, same rules as the gRPC Admin RPCs), Auth Key issue and revoke (plaintext shown once; no key inventory in v1), read-only Policy, health, a backup-only ops action, and a deploy wizard. No User self-service UI.

## HTTP

| 区域 | 路径（示意） | v1 |
|---|---|---|
| 静态页 | `/admin/` | `hz-coord` 现有的 axum HTTP 面 |
| 会话 | `/admin/` 下的 OIDC 回调 | Kanidm；仅 `hznet_admins` |
| Node、Auth Key | `/admin/api/…` | 与 gRPC 同一套 Admin 领域逻辑 |
| Policy | `/admin/api/…` | 只读 |
| 运维 | `/admin/api/…` | 触发打包备份；读取备份与证书健康 |

REST/JSON under something like `/admin/api/…`. The ops whitelist is those two calls. Browsers do not speak gRPC-Web.

## 部署摩擦

这三项是安装与上线时反复手工补的缺口。向导页只把它们指出来；`install.sh`、plist 与健康检查脚本的改动另做。

| 项 | 共识 |
|---|---|
| `HZD_RELAY_ADDR` | `install.sh` 与它写出的 launchd plist 在部署提供了 Relay 地址时写入 `HZD_RELAY_ADDR`。今天两者只写 `HZD_COORD_ADDR`，Relay 要手补（[runbook §6.3](runbook.md)、[§6.4](runbook.md)、[安装手册 §6](install-guide.md)）。升级仍保留用户已经改过的其他键 |
| 健康检查脚本 | 在部署脚本旁加一支只读脚本：汇总 coord 的 `/healthz`、三张单域名证书的到期时间、最近一次 `backup.sh` 快照的新旧。只打印，不重启、不改文件。健康页读同一类事实 |
| 部署向导页 | Admin Console 里的一页，按顺序给出尚未完成的下一步：DNS 与 SNI、证书（[runbook §3](runbook.md)）、Kanidm 与 `hznet_admins`（[§5](runbook.md)）、bootstrap 与首个 Node（[§6](runbook.md)）、Relay 地址、备份 cron（[§7](runbook.md)）。不跑 shell，不 systemctl，不签发证书，不恢复备份。coord 的 HTTP 面还没起来时，仍以 runbook 为准 |

Deploy friction to fix outside this note: write `HZD_RELAY_ADDR` from `install.sh` and the generated plist when the deployment has a Relay address (upgrades keep other keys the operator already set); add a read-only healthcheck script for `/healthz`, the three single-name certificates, and the latest packaged backup; add a wizard page that lists those next steps and links the runbook without running them.

## 不做

- User 自助界面
- 容器或 K8s
- 在浏览器里修改、推送或回滚 Policy
- 经界面或 HTTP 重启、升级
- 任意 shell
- 浏览器走 gRPC-Web
- 单独的 `hz-admin` 进程，或 Vue/React 构建链

Out of scope: User self-service, containers or K8s, Policy edits in the browser, restart or upgrade through the UI or HTTP, arbitrary shell, gRPC-Web, a separate `hz-admin` process, and a Vue or React build.
