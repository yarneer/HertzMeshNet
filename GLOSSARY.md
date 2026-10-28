# HertzMeshNet

一个私有部署的点对点组网系统：让一个组织内分散在各种 NAT 后面的机器，组成一张彼此可直接寻址的加密虚拟网络。

## Language

### 网络

**HzNet**:
一次部署所形成的那张加密虚拟网络。一次部署恰好对应一个 HzNet。
_Avoid_: Mesh, Tailnet, Network, 组网, 虚拟局域网

**Node Address**:
Coordination Server 分配给 Node、在 HzNet 内唯一且稳定的地址（一个 IPv4 加一个 IPv6）。
_Avoid_: Virtual IP, Tunnel IP, 内网 IP

**Node Name**:
Node 在 HzNet 内唯一的可读名字，可用于网内名字解析。
_Avoid_: Hostname（主机名只是 Node Name 的默认来源）, Alias

### 身份与成员

**User**:
组织内的一个人，是 Node 的归属主体与权限判定的主体。
_Avoid_: Account, Member, 用户账号

**Node**:
加入网络的一台设备（服务器、笔记本、虚拟机），拥有独立的密钥身份与网内地址。一个 User 可以拥有多个 Node。
_Avoid_: Machine, Device, Peer, Host, 客户端

**Tag**:
赋予无人值守 Node 的角色标识（如 `tag:db`），带 Tag 的 Node 不归属任何 User，其身份即其 Tag。一个 Node 要么归属一个 User，要么带有一个或多个 Tag，二者互斥。
_Avoid_: Label, Role, 服务账号

**Auth Key**:
由管理员预先签发、用于让 Node 无需交互登录即可注册的凭证，可预先绑定 Tag。
_Avoid_: Pre-auth Key, Token, Join Key, 注册码

**Admin**:
有权管理整个 HzNet（签发 Auth Key、修改 Policy、吊销任意 Node）的 User；其他 User 只能管理自己名下的 Node。
_Avoid_: Owner, Root, 超级用户

**Machine Key**:
代表一台物理设备的长期密钥，在 Node 的整个生命周期内不变，用于 Node 向 Coordination Server 证明身份。
_Avoid_: Device Key, Host Key

**Node Key**:
Node 在数据面使用的 WireGuard 密钥，会在重新登录或到期时轮换；轮换不改变 Node 的身份、Node Address 与 Node Name。
_Avoid_: WireGuard Key, Session Key, Public Key（未加限定时）

### 系统组成

**Coordination Server**:
私有云上集中部署的控制面，负责 Node 的注册、身份认证与网络信息分发；不转发 Node 之间的业务流量。
_Avoid_: Control Server, Controller, Master, 服务端

**Admin Console**:
给 Admin 使用的浏览器界面，用来管理 HzNet（Node 列表、Auth Key、健康状态、有限的运维操作）。
_Avoid_: Dashboard, Portal, Web UI

**Relay**:
带公网入口的中转服务，在两个 Node 无法直连时代为转发已加密的流量。
_Avoid_: DERP, TURN, Proxy, 中继服务器（作为别名可接受，但代码与文档用 Relay）

**Network Map**:
Coordination Server 下发给某个 Node 的 HzNet 视图：仅包含 Policy 允许它访问或允许访问它的那些 Node 及其公钥与 Endpoint。
_Avoid_: Netmap, Peer List, 拓扑, 路由表

**Endpoint**:
可能抵达某个 Node 的一个网络地址（公网或内网的 IP:端口），一个 Node 通常同时有多个候选 Endpoint。
_Avoid_: Address（与 Node Address 混淆）, Candidate

**Direct Path / Relayed Path**:
两个 Node 之间流量的实际走向：经由某个 Endpoint 直达，或经由 Relay 中转。
_Avoid_: P2P 连接, 中继模式

**Health Report**:
Node 周期上报给 Coordination Server 的直连能力与路径状态摘要：UDP 外发是否可用、是否拿到公网映射、上报的 Endpoint 是否可疑，以及哪些对端正走 Relayed Path、原因是什么。只描述"能不能直连、为什么不能"，不含业务流量内容。
_Avoid_: Telemetry, Heartbeat, 心跳, 遥测

**Port Map（端口映射）**:
hzd 经 PCP / NAT-PMP / UPnP IGD 向出口路由器为 WireGuard 端口申请的稳定公网映射，作为优先级高于 STUN 的 Endpoint 候选上报。映射返回的外网地址不是公网（私网 / CGNAT / 198.18.0.0/15）时判定为多重 NAT，不上报该候选。
_Avoid_: 端口转发, DMZ, UPnP 映射（UPnP 只是三种协议之一）

### 访问控制

**Policy**:
描述 HzNet 内谁能访问谁的整份声明式规则；未被 Policy 允许的流量一律拒绝。
_Avoid_: ACL, Rules, Firewall, 权限配置

**Group**:
在 Policy 中定义的一组 User，用作访问规则的主体。
_Avoid_: Team, Role, 部门
