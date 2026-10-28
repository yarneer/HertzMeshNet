# Health Report 只存内存，版本落库；Relay 原因由 hzd 本地判断

Node 的软件版本、操作系统与架构随 `Hello` 上报，写进 `nodes` 表，连同 `last_seen_unix` 一起持久化，离线的 Node 也能看到"最后一次以什么版本在线"。Health Report（直连能力与路径状态，见 [GLOSSARY.md](../../GLOSSARY.md)）随 `ReportEndpoints` 每 30 秒上报，只存在 `hz-coord` 内存里：coord 重启后显示"等待上报"，30 秒内补齐；超过 90 秒未更新视为过期。`last_seen` 在内存实时更新，只在 Network Map 流断开时与每 5 分钟批量落库，避免每个 Node 每 30 秒写一次 SQLite。

某个对端为什么走 Relayed Path，由 hzd 本地判定后上报（`local_udp_broken` → `no_candidates` → `handshake_timeout` → `punch_pending`，取第一条命中）。只有 Node 自己知道打洞信令是否往来、WireGuard 握手是否超时；coord 只看得到双方上报的 Endpoint，推断不出这些。

曾考虑把 Health Report 也落库以保留历史、以及由 coord 从双方 Endpoint 推断路径原因。前者每个 Node 每 30 秒一次写入，而历史趋势已由 Prometheus 承担；后者恰好推断不出 #62 真机验证中遇到的两类问题（安全组未放行导致握手超时、对端缺公网候选），因此不采用。
