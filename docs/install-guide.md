# HzNet Node 安装手册

把一台 Linux 或 macOS 机器加入 HzNet：安装 `hzd`（Node 守护进程）与 `hz`（命令行），注册，验证连通。服务器的部署见 [runbook.md](runbook.md)；本文只做 Node 侧。

## 1. 前提条件

- HzNet 服务器已部署并可访问。你需要两个地址：gRPC 地址（如 `https://coord.example.com:443`）和分发地址（如 `https://coord.example.com:8443`，用于一条命令安装）。没有服务器，先完成 runbook §4 到 §6。
- 支持的平台：Linux x86_64、Linux aarch64、macOS arm64。
- root 权限。`hzd` 要创建 TUN 接口和改路由；macOS 上没有 root 只能完成注册，不能转发流量。
- 机器上有 `curl`，以及 `sha256sum` 或 `shasum` 之一。
- 网络只需出站：Node 不监听公网端口。

## 2. 方式一：一条命令安装

服务器配置了 `--dist-dir` 分发面时，用这条命令。脚本会下载 `hzd` 与 `hz`、做 sha256 校验、写入系统服务并设置开机自启。

```sh
curl -fsSL https://coord.example.com:8443/install.sh | sudo sh
```

把 `coord.example.com:8443` 换成你的分发地址。成功时最后两行输出是：

```
安装完成，运行 hz up 加入 HzNet
（带 Auth Key：hz up --auth-key <Key>；缺省走交互式登录）
```

没有分发面时，用 GitHub Release 的脚本加环境变量，效果相同。`sudo` 默认清掉调用者的环境变量，所以用 `sudo env` 把地址送进脚本：

```sh
curl -fsSL -o install.sh https://github.com/yarneer/HertzMeshNet/releases/latest/download/install.sh
sudo env \
  HZNET_COORD_URL=https://coord.example.com:8443 \
  HZNET_COORD_ADDR=https://coord.example.com:443 \
  sh install.sh
```

`HZNET_COORD_URL` 是下载二进制的分发地址，`HZNET_COORD_ADDR` 是写进配置的 gRPC 地址。两者不同时都要给。标准三子域名下不必再设 Relay：主机名是 `coord.<域名>` 时脚本写成 `HZD_RELAY_ADDR=https://relay.<域名>`。Relay 不在这个名字上时再加 `HZNET_RELAY_ADDR=https://<Relay 主机>`。

脚本做了什么：

- Linux：二进制装入 `/usr/local/bin`；`/etc/default/hzd` 写入 `HZD_COORD_ADDR`，能确定 Relay 地址时同时写入 `HZD_RELAY_ADDR`（已有该变量则保留）；写入并启用 `hzd.service`（systemd）；`/etc/profile.d/hznet.sh` 让登录 shell 也拿到 `HZD_COORD_ADDR`。
- macOS：二进制装入 `/usr/local/bin`；写入并加载 `/Library/LaunchDaemons/com.hznet.hzd.plist`（launchd，`KeepAlive`）。plist 的 `EnvironmentVariables` 含 `HZD_COORD_ADDR`，能确定 Relay 地址时同时含 `HZD_RELAY_ADDR`（已有则保留）。日志在 `/Library/Logs/hzd.log`。

## 3. 方式二：手动安装

适合离线机器或不想跑脚本的场合。资产在 [GitHub Releases](https://github.com/yarneer/HertzMeshNet/releases)，命名是 `hzd-<平台>` 与 `hz-<平台>`，平台取 `linux-x86_64`、`linux-aarch64`、`darwin-arm64`。

1. 下载二进制和 `manifest.json`：

   ```sh
   curl -fsSL -O https://github.com/yarneer/HertzMeshNet/releases/latest/download/hzd-linux-x86_64
   curl -fsSL -O https://github.com/yarneer/HertzMeshNet/releases/latest/download/hz-linux-x86_64
   curl -fsSL -O https://github.com/yarneer/HertzMeshNet/releases/latest/download/manifest.json
   ```

2. 校验 sha256。`manifest.json` 的键是 `<平台>/<二进制>`：

   ```sh
   want=$(sed -n 's|^.*"linux-x86_64/hzd":{"sha256":"\([0-9a-f]*\)".*|\1|p' manifest.json)
   echo "$want  hzd-linux-x86_64" | sha256sum -c
   ```

3. 装入 `/usr/local/bin` 并启动服务。Linux 用仓库里的单元文件：

   ```sh
   sudo install -m 0755 hzd-linux-x86_64 /usr/local/bin/hzd
   sudo install -m 0755 hz-linux-x86_64 /usr/local/bin/hz
   printf '%s\n' \
     'HZD_COORD_ADDR=https://coord.example.com:443' \
     'HZD_RELAY_ADDR=https://relay.example.com' | sudo tee /etc/default/hzd
   sudo cp packaging/systemd/hzd.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now hzd
   ```

   macOS 写入 launchd。用仓库里的 [packaging/launchd/com.hznet.hzd.plist](../packaging/launchd/com.hznet.hzd.plist)，把 `HZD_COORD_ADDR` 与 `HZD_RELAY_ADDR` 填进 plist 的 `EnvironmentVariables` 段（launchd 不继承 shell 环境变量），然后：

   ```sh
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.hznet.hzd.plist
   ```

## 4. 注册加入

两种方式，选一种。

**用 Auth Key。** 管理员先在自己已加入的机器上签发（需要 Admin）：

```sh
sudo hz authkey create --expiry 7d --once --tag server
```

输出是 `auth_key`（明文只显示这一次）和 `key_id`（吊销时用，记下来）。`--once` 表示用一次即作废；`--tag <名字>` 必填（可多次）：用 Auth Key 注册的 Node 不归属任何 User，身份就是它的 Tag，Policy 以 `tag:<名字>` 引用它。要让机器归属到某个人，用下面的交互式登录。然后在目标机器上：

```sh
sudo hz up --auth-key <auth_key>
```

**交互式登录。** 不带 Key 直接运行：

```sh
sudo hz up
```

终端会打印一个一次性登录链接（短时效、只能用一次）。把链接复制到任意设备的浏览器完成登录，这台机器随即加入并归属到登录的 User。机器上不保存任何 IdP 凭证。

已经注册过的机器重新归属 User（有效期到期后重新登录），用 `sudo hz login`。身份、Node Address 和 Node Name 保持不变。

## 5. 验证

1. 看本机身份（只读查询，普通用户即可执行）：

   ```sh
   hz status
   ```

   期望输出包含 `已加入 HzNet`、本机的 Node Name 与 Node Address（形如 `100.96.0.1`）。

2. 探测一个对端（把 `db-1` 换成对端 Node Name）：

   ```sh
   hz ping db-1
   ```

   期望显示往返时延和走的路径（`Direct Path` 或 `Relayed Path`）。

3. 用域名解析互 ping：

   ```sh
   ping db-1.hznet.internal
   ```

   期望与 `hz ping` 一致。Linux 上 `hzd` 通过 systemd-resolved 接管 `hznet.internal` 后缀，macOS 上写 `/etc/resolver/hznet.internal`；两者都只接管这个后缀。

## 6. Relay 地址

标准三子域名（Coordination Server 在 `coord.<域名>`，Relay 在 `relay.<域名>`，ADR-0004）时，一条命令安装会写入 `HZD_RELAY_ADDR=https://relay.<域名>`：Linux 写 `/etc/default/hzd`，macOS 写 plist 的 `EnvironmentVariables`。重跑安装若发现已经有 `HZD_RELAY_ADDR`，原样保留，不覆盖。

Relay 不在 `relay.<域名>` 上时，安装前设置 `HZNET_RELAY_ADDR`（`sudo` 会清环境变量，用 `sudo env`，与第 2 节相同）：

```sh
# 仓库或 GitHub Release 里的 install.sh
sudo env HZNET_RELAY_ADDR=https://relay.example.com:8443 sh install.sh

# 从 Coordination Server 拉下来的脚本。标准三子域名不必设这个变量
curl -fsSL https://coord.example.com/install.sh | sudo env HZNET_RELAY_ADDR=https://relay.example.com:8443 sh
```

从 Coordination Server 拉下来的 `install.sh` 已经带好 gRPC 地址，推导或上面的变量都在脚本内部完成，一般不必再手改文件。方式二的手动安装不会推导，按第 3 节把 `HZD_RELAY_ADDR` 和 `HZD_COORD_ADDR` 一起写入。

hzd 只认环境变量 `HZD_RELAY_ADDR`，没有对应的命令行 flag。Relay 使用私有 CA 时还要加 `HZD_RELAY_CA_PATH=<PEM 路径>`（Linux 追加到 `/etc/default/hzd` 后 `sudo systemctl restart hzd`；macOS 加进同一个 `EnvironmentVariables` 字典后重新 bootstrap）。细节见 [runbook.md](runbook.md) §6.3 与 §6.4。

## 7. 升级

重跑安装命令即可。脚本检测到 `hzd` 在运行会替换二进制并重启服务；注册身份保留在状态目录（Linux `/var/lib/hzd`，macOS `/Library/Application Support/hzd`），升级后无需重新注册。手动安装的机器重复第 3 节的步骤后 `sudo systemctl restart hzd`。

升级保留已有配置：Linux 保留 `/etc/default/hzd` 里除 `HZD_COORD_ADDR` 以外的变量，macOS 保留 plist `EnvironmentVariables` 里除 `HZD_COORD_ADDR` 以外的键（改过的 `HZD_RELAY_ADDR`、`HZD_STUN_ADDR`、`HZD_BOOTSTRAP_DNS` 等）。`HZD_COORD_ADDR` 换成本次安装的值。还没有 `HZD_RELAY_ADDR`、且本次能确定 Relay 地址时，升级会补上。0.1.3 及更早版本的脚本升级时会整份重写这两个文件，用这些版本升级过的机器请检查 Relay 等配置是否还在，缺了按第 6 节补回。

macOS 上脚本会等旧 `hzd` 完全退出（它退出前要先恢复 DNS 配置，通常几秒）再重新加载服务，并确认新 `hzd` 已在运行才报告「已启动」。等待超时或加载失败时脚本报错退出，按提示的命令查看日志并手动加载，或见第 9 节。

## 8. 卸载

Linux：

```sh
sudo systemctl disable --now hzd
sudo rm /etc/systemd/system/hzd.service /etc/default/hzd /etc/profile.d/hznet.sh
sudo rm /usr/local/bin/hzd /usr/local/bin/hz
sudo rm -rf /var/lib/hzd
```

macOS：

```sh
sudo launchctl bootout system/com.hznet.hzd
sudo rm /Library/LaunchDaemons/com.hznet.hzd.plist
sudo rm /usr/local/bin/hzd /usr/local/bin/hz
sudo rm -rf "/Library/Application Support/hzd" /Library/Logs/hzd.log /etc/resolver/hznet.internal
```

删除状态目录即删除本机身份（Machine Key 与 Node Key）。想保留身份以后再加入，跳过最后一条 `rm`。

## 9. 常见问题

- **提示「需要 root」**：安装与 `hz up` 都要 root，用 `sudo`。
- **`hz status` 报「无法连接 hzd」**：`hzd` 没在运行。Linux 用 `systemctl status hzd`、macOS 用 `sudo tail /Library/Logs/hzd.log` 查原因。
- **`hz status` 报 Permission denied，同时 `hz up` 报 Connection refused**：`hzd` 没在运行，留下的是旧版本退出时未清理的 `/var/run/hzd.sock`（新版 `hzd` 启动时会自行删除重建，无需手动处理）。常见于升级过程中服务被卸载后没重新加载。检查并恢复：

  macOS：

  ```sh
  sudo launchctl print system/com.hznet.hzd | grep -E 'state|pid'   # 报「Could not find service」即未加载
  sudo tail -n 50 /Library/Logs/hzd.log
  sudo launchctl bootstrap system /Library/LaunchDaemons/com.hznet.hzd.plist
  ```

  Linux：

  ```sh
  systemctl status hzd
  sudo journalctl -u hzd -n 50
  sudo systemctl enable --now hzd
  ```

  恢复后 `hz status` 应正常输出。若 `bootstrap` 报 `Bootstrap failed: 5: Input/output error`，说明旧进程还没退出完，等几秒再执行一次。
- **安装脚本报「未获知服务器地址」**：脚本是从 GitHub 下载的原件，按第 2 节带上 `HZNET_COORD_URL` 与 `HZNET_COORD_ADDR` 再运行。
- **注册时报「Auth Key 已使用」或「Auth Key 已过期」**：一次性 Key 只能用一次，过期 Key 向签发人重新要一把。
- **`hz` 命令提示「需要管理员权限，请用 sudo 执行」**：`hz status`、`hz ping`、`hz netcheck` 是只读查询，普通用户即可执行；`hz up`、`hz login`、Policy、Auth Key 与 Node 管理会以本 Node 的身份改动状态，需要 `sudo`。
- **只能走中转（一直是 Relayed Path）**：先运行 `hz netcheck`（只读，不需要 root）。它会一次给出物理出口和默认路由持有者、IPv4/IPv6 UDP 外发是否失败及底层错误（例如 `IPv4 UDP 外发失败：EINVAL`）、STUN 映射与 NAT 类型、上报给 Coordination Server 的 Endpoint（`198.18.0.0/15`、回环、虚拟网卡地址会标出）、是否有可用 IPv6、到 Relay 的 RTT，以及每个对端的路径和最近一次打洞结果。加 `--json` 给脚本用。
- **`hz status` 提示「流量被其他隧道接管」或「名字解析被接管」**：本机有其他网络工具在接管路由或 DNS，见第 10 节。
- **macOS 上注册成功但 ping 不通**：`hzd` 需要 root 创建 utun；确认它是经 launchd 以 root 运行的（`sudo launchctl print system/com.hznet.hzd`）。
- **改了地址段要重装吗**：地址段是服务器侧的部署决定（runbook §9）。Node 无需配置，注册响应会携带生效段。

## 10. 与第三方 TUN 类网络工具共存

一些网络工具会创建自己的虚拟网卡，接管系统的默认路由与 DNS。它们与 HzNet 同时运行时可能互相干扰。

### 10.1 现象

- `ping` 对端看似能通，但 SSH 等 TCP 连接建立后立即被断开（`Connection closed by remote host`）；
- 用名字（`xxx.hznet.internal`）访问失败，而且任意名字都被解析成 `198.18.x.x`；
- 关掉那个工具后反而不通（它留下或删除了与 HzNet 相关的路由）。

### 10.2 自检

```sh
hz status
```

发现冲突时会直接给出提示：

- **流量被其他隧道接管**：发往 HzNet 的流量实际从别的网卡发出，提示中给出实际源地址和网卡名；
- **名字解析被接管**：HzNet 域名后缀被解析成 `198.18.0.0/15` 内的假地址。

`hz status --json` 的 `conflicts` 字段给出同样的结构化结果，便于脚本判断。

### 10.3 hzd 会自动处理的部分

- **连接服务器时的域名解析**：系统 DNS 对 Coordination Server、Relay、STUN 的域名返回 `198.18.x.x` 假地址时，`hzd` 会绕过系统 DNS，经物理网卡直接向引导 DNS 查询，并缓存最近一次有效结果。引导 DNS 默认取本机通过 DHCP 获得的 DNS，再退到公共 DNS；可用环境变量 `HZD_BOOTSTRAP_DNS`（逗号分隔，如 `223.5.5.5,119.29.29.29`）指定。
- **HzNet 路由**：被删除或被其他网卡的同前缀路由占用时，`hzd` 在 10 秒内自动恢复，无需重启。

`hz status` 会显示最近一次发生的引导 DNS 回退与路由修复。

### 10.4 需要在对方工具里配置的部分

1. **把 HzNet 地址段排除在它的隧道之外，但不要排除与 HzNet 完全相同的前缀。** 排除完全相同的前缀（例如 HzNet 段是 `10.213.0.0/16`，就排除 `10.213.0.0/16`）会让它安装一条同前缀、走物理网关的路由，顶掉 HzNet 的路由；它关闭时又连同删除，HzNet 随之失去路由。应排除一个**更宽**的范围，例如 `10.0.0.0/8`（HzNet 段在 `10.x` 时）或 `100.64.0.0/10`（默认段 `100.96.0.0/16` 时），以及 HzNet 的 ULA IPv6 段所在的更宽范围（如 `fd00::/8`）。HzNet 自己更具体的路由仍然优先。
2. **把 HzNet 域名后缀交给 HzNet 的本地 DNS 解析**，不要让它分配假地址。本地 DNS 地址是 HzNet 段内的保留地址（默认 `100.96.0.53`；改过地址段时为该段网络地址末位换成 53，macOS 上可在 `/etc/resolver/hznet.internal` 中看到）。很多工具支持按域名指定上游 DNS，或把某些域名加入假地址的例外列表。
3. 只加一条"直连"规则通常**不够**：直连意味着由该工具从物理网卡把流量重新发出，而物理网卡到不了 HzNet。

#### 配置示例

以下以 HzNet 段 `10.213.0.0/16`、ULA 段 `fd7a:3548:1873::/48`、本地 DNS `10.213.0.53`、域名后缀 `hznet.internal` 为例，按你的实际值替换；`hz status` 的冲突提示会给出需要排除的地址段。

**INI 风格配置**（`[General]` 段里的排除路由与跳过代理列表、`[Host]` 段里的按域名指定 DNS；在原有值后追加，不要删除原有内容）：

```ini
[General]
tun-excluded-routes = <原有内容>, 10.0.0.0/8, fd00::/8
skip-proxy = <原有内容>, 10.0.0.0/8, *.hznet.internal

[Host]
*.hznet.internal = server:10.213.0.53
```

**YAML 风格配置**（TUN 的排除地址、假地址例外列表与按域名指定 DNS）：

```yaml
tun:
  route-exclude-address:
    - 10.0.0.0/8
    - fd00::/8
dns:
  fake-ip-filter:
    - "+.hznet.internal"
  nameserver-policy:
    "+.hznet.internal": 10.213.0.53
```

不同工具、不同版本的字段名可能略有差异，以其文档为准；要点是三件事：排除比 HzNet 段更宽的范围、HzNet 域名后缀不分配假地址、并交给 HzNet 本地 DNS 解析。

配置改完后需要断开再重新连接该工具，排除规则才会生效；之后用 `hz status` 确认没有冲突提示。

### 10.5 已知限制（macOS）

macOS 上，基于系统 Network Extension 的工具可以"强制接管路由"：此时系统按它的规则转发，路由表中 HzNet 更具体的路由也不起作用，`route get` 显示的结果与实际转发不一致。这种情况下只能依靠第 10.4 节在该工具里排除 HzNet 地址段；如果该工具不支持排除，使用 HzNet 时请先关闭它。


## 11. 路由器端口映射与多重 NAT（v0.3）

处于对称型 NAT（`hz netcheck` 显示 `NAT：hard`）后的两台机器互相无法直连。
hzd 会依次尝试 **PCP / NAT-PMP / UPnP IGD**，向出口路由器为 WireGuard 端口
申请一个稳定、与目的地址无关的公网映射，作为优先级高于 STUN 的候选上报，
让 hard NAT 后的 Node 也能直连。为此需要：

1. **路由器开启其中一种映射协议**：管理界面里通常叫「UPnP」（或「NAT-PMP /
   PCP」）。多数家用路由器默认开启；MiWiFi 等可在「高级设置 → 端口映射 /
   UPnP」里找到。
2. **路由器拿到公网 IP**：如果 `hz netcheck` 提示「多重 NAT：路由器上游还有
   NAT」，说明路由器上面还有一层（通常是光猫在做路由）。把光猫改成**桥接
   模式**、让路由器直接拨号，端口映射才会返回真正的公网地址；在那之前
   hzd 不会上报这个映射（无意义的私网候选）。
3. 不希望 hzd 修改路由器配置的网络（公司、共享网络）：设 `HZD_PORTMAP=0`
   关闭，hzd 不发起任何映射请求。

映射的租期到一半会自动续租，网络切换（Wi-Fi ↔ 有线）后重新申请，hzd 退出
时尽力删除。验证：`hz netcheck` 的「端口映射」一行会显示协议与外网地址，
如 `端口映射：NAT-PMP，外网 1.2.3.4:51820`。

> macOS 与 Linux 均支持；申请报文经物理出口网卡发出，与第三方 TUN 类工具
> 共存（见第 10 节）。
