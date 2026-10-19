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

没有分发面时，用 GitHub Release 的脚本加两个环境变量，效果相同：

```sh
curl -fsSL -o install.sh https://github.com/yarneer/HertzMeshNet/releases/latest/download/install.sh
HZNET_COORD_URL=https://coord.example.com:8443 \
HZNET_COORD_ADDR=https://coord.example.com:443 \
sudo sh install.sh
```

`HZNET_COORD_URL` 是下载二进制的分发地址，`HZNET_COORD_ADDR` 是写进配置的 gRPC 地址。两者不同时都要给。

脚本做了什么：

- Linux：二进制装入 `/usr/local/bin`；`/etc/default/hzd` 写入 `HZD_COORD_ADDR`；写入并启用 `hzd.service`（systemd）；`/etc/profile.d/hznet.sh` 让登录 shell 也拿到 `HZD_COORD_ADDR`。
- macOS：二进制装入 `/usr/local/bin`；写入并加载 `/Library/LaunchDaemons/com.hznet.hzd.plist`（launchd，`KeepAlive`）；日志在 `/Library/Logs/hzd.log`。

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
   echo 'HZD_COORD_ADDR=https://coord.example.com:443' | sudo tee /etc/default/hzd
   sudo cp packaging/systemd/hzd.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now hzd
   ```

   macOS 写入 launchd。用仓库里的 [packaging/launchd/com.hznet.hzd.plist](../packaging/launchd/com.hznet.hzd.plist)，把 `HZD_COORD_ADDR` 环境变量填进 plist 的 `EnvironmentVariables` 段（launchd 不继承 shell 环境变量），然后：

   ```sh
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.hznet.hzd.plist
   ```

## 4. 注册加入

两种方式，选一种。

**用 Auth Key。** 管理员先在自己已加入的机器上签发（需要 Admin）：

```sh
sudo hz authkey create --expiry 7d --once
```

输出是 `auth_key`（明文只显示这一次）和 `key_id`（吊销时用，记下来）。`--once` 表示用一次即作废；`--tag <名字>` 可预绑定 Tag。然后在目标机器上：

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

1. 看本机身份：

   ```sh
   sudo hz status
   ```

   期望输出包含 `已加入 HzNet`、本机的 Node Name 与 Node Address（形如 `100.96.0.1`）。

2. 探测一个对端（把 `db-1` 换成对端 Node Name）：

   ```sh
   sudo hz ping db-1
   ```

   期望显示往返时延和走的路径（`Direct Path` 或 `Relayed Path`）。

3. 用域名解析互 ping：

   ```sh
   ping db-1.hznet.internal
   ```

   期望与 `hz ping` 一致。Linux 上 `hzd` 通过 systemd-resolved 接管 `hznet.internal` 后缀，macOS 上写 `/etc/resolver/hznet.internal`；两者都只接管这个后缀。

## 6. 补充 Relay 地址

默认安装只写 `HZD_COORD_ADDR`。你的部署如果用独立 Relay 域名（runbook §1 的三子域名形态），把 Relay 地址加进配置并重启，否则跨 NAT 的流量没有中转路径：

- Linux：在 `/etc/default/hzd` 追加 `HZD_RELAY_ADDR=<relay 地址>`，然后 `sudo systemctl restart hzd`。
- macOS：在 plist 的 `EnvironmentVariables` 段加同样的键值，然后 `sudo launchctl bootout system/com.hznet.hzd && sudo launchctl bootstrap system /Library/LaunchDaemons/com.hznet.hzd.plist`。

Relay 使用私有 CA 时还要加 `HZD_RELAY_CA_PATH=<PEM 路径>`。细节见 [runbook.md](runbook.md) §6.3 与 §6.4。

## 7. 升级

重跑安装命令即可。脚本检测到 `hzd` 在运行会替换二进制并重启服务；注册身份保留在状态目录（Linux `/var/lib/hzd`，macOS `/Library/Application Support/hzd`），升级后无需重新注册。手动安装的机器重复第 3 节的步骤后 `sudo systemctl restart hzd`。

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
- **安装脚本报「未获知服务器地址」**：脚本是从 GitHub 下载的原件，按第 2 节带上 `HZNET_COORD_URL` 与 `HZNET_COORD_ADDR` 再运行。
- **注册时报「Auth Key 已使用」或「Auth Key 已过期」**：一次性 Key 只能用一次，过期 Key 向签发人重新要一把。
- **`hz` 命令报权限错误**：`hz` 经本地 socket 与 `hzd` 通信，遇到权限错误时加 `sudo` 重试。
- **macOS 上注册成功但 ping 不通**：`hzd` 需要 root 创建 utun；确认它是经 launchd 以 root 运行的（`sudo launchctl print system/com.hznet.hzd`）。
- **改了地址段要重装吗**：地址段是服务器侧的部署决定（runbook §9）。Node 无需配置，注册响应会携带生效段。
