# IPC 成员档按当前交互式会话用户放行

`hzd` 的本地 IPC 方法分三档：只读档（`status`、`ping`、`netcheck`）任何本机用户可调；成员档（交互式登录与邀请码的 `up`、`login_poll`、`down`、`subscribe`、`diagnostics`）只放行当前交互式会话用户（macOS 为 `/dev/console` 的属主）以及 root；管理档（带 Auth Key 的 `up` 和 Policy、Auth Key、邀请码、Node 管理）仍只给 root 或与 hzd 同 uid。这样以普通用户身份运行的 Client App 能完成接入与开关，而签发凭证、改 Policy 这类以本 Node 身份做管理的操作仍需 sudo。

曾考虑要求 admin 组成员，以及经 `LOCAL_PEERPID` 校验调用方进程的代码签名 Team ID。前者把非管理员的普通员工挡在门外；后者最严，但会把同样需要 up / down 的 `hz` CLI 也挡住，且签名校验在 Linux 与将来的 Windows 上没有对等物。"当前交互式会话用户"在三个平台都有明确定义，坐在机器前的人本来就能拔网线，让他开关隧道不扩大攻击面。
