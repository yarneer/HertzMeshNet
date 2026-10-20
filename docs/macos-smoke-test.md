# macOS 手工冒烟测试清单（#16）

规格 §5：macOS 只做手工冒烟。以下步骤在 macOS arm64 真机上、以 root 与
普通用户配合执行；每一节都给出预期输出。执行前准备：

- 一台 Linux Node（同版本 hzd，已 `hz up` 注册），记它的 Node Name 为 `<linux-node>`。
- Coordination Server 与 Relay 可达，Auth Key 一个（`hz-coord bootstrap`）。
- macOS 侧二进制：`cargo build --release -p hzd -p hz`，产物在
  `target/release/`；把 `hzd`、`hz` 放进 PATH（如 `/usr/local/bin/`）。

约定：`$HZD_STATE_DIR` 未设置时默认 `/Library/Application Support/hzd`；
UDS 默认 `/var/run/hzd.sock`。

## 1. launchd 安装并启动（root）

```sh
sudo hzd install-launchd
sudo launchctl load -w /Library/LaunchDaemons/com.hznet.hzd.plist
```

预期：

- `install-launchd` 打印"已写入 /Library/LaunchDaemons/com.hznet.hzd.plist"
  与加载/卸载/日志三行提示。
- `sudo launchctl list | grep com.hznet.hzd` 出现一行，第二列 PID 非 `-`。
- `tail -f /Library/Logs/hzd.log` 里有 `hzd starting`（state_dir=/Library/Application Support/hzd）。
- `ls "/Library/Application Support/hzd"` 出现 machine/node 密钥文件（0600）。

未注册阶段先直接做一次前台冒烟（可选，与 launchd 二选一）：

```sh
sudo hzd   # 前台运行，日志在 stderr；Ctrl-C 退出
```

## 2. 注册（Auth Key 路径）

```sh
sudo hz up --auth-key <auth-key> --coord http(s)://<coord-addr>
hz status
```

预期：

- `hz up` 输出注册成功的 Node 信息（Node Name、Node Address）。
- `hz status` 显示 `已注册`（Registered）与本机 Node Address。
- 日志出现 `utun device configured`（iface=utunN，ipv4=100.96.x.x）。

交互式登录路径（FR-2，与 Auth Key 等价）：`sudo hz up` 不带 `--auth-key`，
按提示完成浏览器登录后 `hz status` 同样显示 Registered。

## 3. utun 与路由（root 核对）

```sh
ifconfig | grep -A3 utun   # 找到 hzd 创建的那个 utunN（MTU 1280，inet 100.96.x.x）
netstat -rn | grep 100.96
```

预期：

- 某个 `utunN` 拥有 `inet 100.96.x.x --> 100.96.x.x` 与 `inet6 fd..:../128`，
  `mtu 1280`。
- 路由表有 `100.96.0.0/16 ... utunN` 与本部署 ULA /48 的 `-inet6` 路由；
- **不得出现** `100.64.0.0/10` 进 utun 的路由（ADR-0003）。

## 4. 与 Linux Node 互通：Direct Path 与 Relayed Path

```sh
hz ping <linux-node>          # 交替观察 path 字段
hz status
```

预期（对照 FR-7/FR-8 验收）：

- 配置了 Relay（HZD_RELAY_ADDR，经 plist 的 EnvironmentVariables 或前台
  环境）时，冷启动先 `path: relay`，打洞成功后 `hz ping` 变 `path: direct`
  且 `endpoint` 是对端真实地址；RTT 数量级正常（LAN 个位数 ms）。
- 在 Linux Node 上反向 `ping <mac-node>` 同样通。
- 双向互发流量（如 `ping 100.96.x.x` 直接 ping 对端 Node Address）可达。

## 5. 网内名字解析（/etc/resolver）

```sh
ls -l /etc/resolver/hznet.internal && cat /etc/resolver/hznet.internal
scutil --dns | grep -A3 hznet
dscacheutil -q host -a name <linux-node>.hznet.internal
ping <linux-node>.hznet.internal
```

预期：

- `/etc/resolver/hznet.internal` 存在，内容 `nameserver 100.96.0.53`。
- `scutil --dns` 出现 domain `hznet.internal` 指向 100.96.0.53 的 resolver。
- `dscacheutil` 返回对端 Node Address；`ping <linux-node>.hznet.internal`
  能通（FR-5 验收原文）。

## 6. 停止后系统 DNS 恢复

```sh
sudo launchctl unload -w /Library/LaunchDaemons/com.hznet.hzd.plist
ls /etc/resolver/
scutil --dns | grep -c hnet   # 应为 0
ping example.com              # 普通解析不受影响
```

预期：

- `hzd` 停止后 `/etc/resolver/hznet.internal` 被删除（启动前就存在的文件
  则逐字节还原）。
- `scutil --dns` 不再有 hznet.internal 条目；普通域名解析正常
  （FR-5 验收：hzd 停止后系统 DNS 恢复）。
- utun 设备随进程退出消失，`netstat -rn` 不再有 100.96/16 路由。

## 7. 第三方 TUN 类网络工具共存（IP_BOUND_IF，FR-7 验收）

先开启一个接管默认路由的第三方 TUN 类网络工具（全局模式），确认：

```sh
route -n get default | grep interface   # 预期显示第三方工具的 utunM
```

再启动 hzd（launchd load 或前台 sudo hzd），然后：

```sh
tail /Library/Logs/hzd.log | grep "physical egress"
hz status                               # 应正常显示注册与对端
hz ping <linux-node>                    # 仍应通（direct 或 relay 皆可）
sudo tcpdump -i en0 -n udp port <HZD_WG_PORT> or udp port 3478   # 可选：肉眼确认外层包从物理网卡出
```

预期：

- 日志 `physical egress interface detected` / `outer traffic bound to physical
  egress` 指向物理网卡（en0/en1…），不是第三方工具的 utun。
- STUN 发现的公网 Endpoint 是本机真实出口地址：日志 `stun mapped endpoint
  discovered` 的地址与物理出口一致（不是第三方工具的出口）。
- `hz ping <linux-node>` 仍通；发往 100.96.0.0/16 的流量走 hzd 的 utun，
  不进第三方工具的虚拟网卡（`netstat -rn | grep 100.96` 仍指向 hzd 的 utun）。
- 关掉第三方工具后 HzNet 依然通（出口探测回到默认路由）。

## 8. 网络切换（出口监视）

Wi-Fi 与有线之间切换（或开关 Wi-Fi）后等待 10 秒内：

- 日志出现 `physical egress interface changed`（from/to 各一张网卡）。
- 切换后新建的外层连接正常：`hz ping <linux-node>` 仍通。

## 9. 运行中路由自愈（#24）

在 hzd 运行、与 Linux Node 互通的前提下（`<段>` 为 HzNet IPv4 段，默认
`100.96.0.0/16`；`<utun>` 为 hzd 的 utun）：

```bash
sudo route -n delete -net <段>                       # 模拟路由被删除
sleep 10; route -n get -net <段> | grep interface    # 应回到 <utun>
sudo route -n add -net <段> 192.168.x.1              # 模拟被物理网关同前缀路由占用
sleep 10; route -n get -net <段> | grep interface    # 应再次回到 <utun>
```

预期：

- 两次都在 10 秒内恢复，`hz ping <linux-node>` 随即可通，无需重启 hzd。
- 日志分别出现 `HzNet 路由被删除，已重新安装` 与 `HzNet 路由被其他网卡（en0）的
  同前缀路由占用，已夺回`（`taken_by=en0`）。
- 路由正常期间日志没有路由自检相关的输出。

## 记录

执行人把每节的实际输出（命令 + 关键行）贴回本文件末尾或 issue #16，
标注 macOS 版本、机型与对端 Linux Node 信息。
