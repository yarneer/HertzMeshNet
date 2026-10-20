#!/bin/sh
# HzNet 一条命令安装（FR-13）。hz-coord 在 serve 时把
# @@HZNET_COORD_URL@@（HTTP 分发面）与 @@HZNET_COORD_GRPC_ADDR@@（gRPC 面）
# 替换成 --public-url / --public-grpc-addr 的值；直接运行仓库原件时占位符
# 未替换，靠 HZNET_COORD_URL / HZNET_COORD_ADDR 环境变量兜底。
set -eu

fail() { echo "安装失败：$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "需要 root，请用 sudo 运行（curl -fsSL <服务器>/install.sh | sudo sh）"

COORD_URL="${HZNET_COORD_URL:-@@HZNET_COORD_URL@@}"
GRPC_ADDR="${HZNET_COORD_ADDR:-@@HZNET_COORD_GRPC_ADDR@@}"
case "$COORD_URL" in
  http://*|https://*) ;;
  *) fail "未获知服务器地址：请设置 HZNET_COORD_URL=http://<coord>:<端口> 再运行，或让服务器以 --public-url 重新提供 install.sh" ;;
esac
case "$GRPC_ADDR" in
  http://*|https://*) ;;
  *) fail "未获知 Coordination Server gRPC 地址：请设置 HZNET_COORD_ADDR=http(s)://<coord>:<端口>，或让服务器以 --public-grpc-addr 重新提供 install.sh" ;;
esac

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) PLATFORM=linux-x86_64 ;;
  Linux:aarch64|Linux:arm64) PLATFORM=linux-aarch64 ;;
  Darwin:arm64) PLATFORM=darwin-arm64 ;;
  *) fail "不支持的平台 $(uname -s)/$(uname -m)（支持 Linux x86_64/aarch64 与 macOS arm64）" ;;
esac

command -v curl >/dev/null 2>&1 || fail "缺少 curl，请先安装（apt-get install -y curl 或 brew install curl）"

if command -v sha256sum >/dev/null 2>&1; then
  file_sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  file_sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "缺少 sha256sum 或 shasum，无法校验二进制"
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

fetch() { curl -fsSL -o "$2" "$1" || fail "下载失败：$1"; }

manifest_sha() {
  sed -n "s|^.*\"$1\":{\"sha256\":\"\([0-9a-f]*\)\".*|\1|p" "$STAGE/manifest.json"
}

fetch "$COORD_URL/dl/manifest.json" "$STAGE/manifest.json"

install_one() {
  name=$1
  fetch "$COORD_URL/dl/$PLATFORM/$name" "$STAGE/$name"
  want=$(manifest_sha "$PLATFORM/$name")
  [ -n "$want" ] || fail "manifest 缺少 $PLATFORM/${name}，服务器分发包不完整"
  got=$(file_sha "$STAGE/$name")
  [ "$got" = "$want" ] || fail "$name sha256 校验失败（期望 ${want}，实际 ${got}）"
  install -m 0755 "$STAGE/$name" "/usr/local/bin/$name"
  echo "已安装 /usr/local/bin/${name}（sha256 ${got}）"
}

mkdir -p /usr/local/bin
install_one hzd
install_one hz

OS=$(uname -s)
if [ "$OS" = "Linux" ]; then
  # 升级时保留用户已有的变量（HZD_RELAY_ADDR 等，见安装手册第 6 节），
  # 只用本次的值替换 HZD_COORD_ADDR。写回用 cat > 而非 mv，保留原文件属主与权限。
  ENV_FILE=/etc/default/hzd
  {
    echo "HZD_COORD_ADDR=$GRPC_ADDR"
    if [ -f "$ENV_FILE" ]; then
      grep -Ev '^[[:space:]]*(export[[:space:]]+)?HZD_COORD_ADDR=' "$ENV_FILE" || true
    fi
  } > "$STAGE/hzd.env"
  cat "$STAGE/hzd.env" > "$ENV_FILE"
  # 与 packaging/systemd/hzd.service 保持一致；随脚本内嵌以免安装时再拉取
  cat > /etc/systemd/system/hzd.service <<'UNIT'
[Unit]
Description=HzNet Node 守护进程
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/default/hzd
ExecStart=/usr/local/bin/hzd
Restart=always
RestartSec=2
StateDirectory=hzd

[Install]
WantedBy=multi-user.target
UNIT
  # hz 客户端也读 HZD_COORD_ADDR；登录 shell 注入后 `hz up` 不必带 --coord
  cat > /etc/profile.d/hznet.sh <<EOF
export HZD_COORD_ADDR=$GRPC_ADDR
EOF
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable hzd >/dev/null
    if systemctl is-active --quiet hzd; then
      systemctl restart hzd
      echo "已重启 hzd（升级到新版本），开机自启保持开启"
    else
      systemctl start hzd
      echo "已启动 hzd 并设置开机自启"
    fi
  else
    echo "警告：未检测到 systemd（容器或最小系统？），已写入 /etc/systemd/system/hzd.service 与 /etc/default/hzd；进入 systemd 环境后执行 systemctl enable --now hzd"
  fi
else
  # 与 packaging/launchd/com.hznet.hzd.plist 同形态，额外注入 HZD_COORD_ADDR
  # （launchd 不继承 shell 环境变量）。先写到临时目录，合并旧配置后再落盘。
  PLIST=/Library/LaunchDaemons/com.hznet.hzd.plist
  LABEL=system/com.hznet.hzd
  cat > "$STAGE/hzd.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hznet.hzd</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/hzd</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HZD_COORD_ADDR</key>
        <string>$GRPC_ADDR</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/hzd.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/hzd.log</string>
</dict>
</plist>
EOF
  # 升级时保留旧 plist EnvironmentVariables 里用户加的键（HZD_RELAY_ADDR、
  # HZD_STUN_ADDR、HZD_BOOTSTRAP_DNS 等，见安装手册第 6 节）。Merge 遇到同名键
  # 跳过并保留新模板里的值，所以 HZD_COORD_ADDR 取本次的值、其余键原样带过来；
  # 值整体以 plist 搬运，路径里的空格与引号不经 shell 转义。
  if [ -f "$PLIST" ] && plutil -extract EnvironmentVariables xml1 -o "$STAGE/env.plist" "$PLIST" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Merge $STAGE/env.plist :EnvironmentVariables" "$STAGE/hzd.plist" >/dev/null \
      || fail "无法合并 $PLIST 中已有的环境变量；原文件未改动，请检查其 EnvironmentVariables 段"
    echo "已保留 $PLIST 中已有的环境变量（HZD_COORD_ADDR 更新为 ${GRPC_ADDR}）"
  fi
  plutil -lint "$STAGE/hzd.plist" >/dev/null || fail "生成的 plist 格式错误"
  install -o root -g wheel -m 0644 "$STAGE/hzd.plist" "$PLIST"

  # bootout 只是请求卸载：旧 hzd 收到 SIGTERM 后要先恢复 DNS 配置才退出，
  # 这期间服务仍登记在 launchd 里。此时立即 bootstrap 会报
  # "Bootstrap failed: 5: Input/output error"，服务就停在已卸载、未重载的状态。
  # 所以等到 launchctl print 查不到服务（已彻底卸载）再 bootstrap，最多 15 秒。
  launchctl bootout "$LABEL" >/dev/null 2>&1 || true
  waited=0
  while launchctl print "$LABEL" >/dev/null 2>&1; do
    [ "$waited" -lt 30 ] || fail "旧 hzd 15 秒内未退出，服务未重载。查看日志：sudo tail -n 50 /Library/Logs/hzd.log；确认旧进程退出后执行：sudo launchctl bootstrap system $PLIST"
    sleep 0.5
    waited=$((waited + 1))
  done
  launchctl bootstrap system "$PLIST" \
    || fail "launchd 未能加载 hzd。查看日志：sudo tail -n 50 /Library/Logs/hzd.log；稍后重试：sudo launchctl bootstrap system $PLIST"

  # bootstrap 成功只代表 launchd 接受了配置；确认 hzd 进程真的跑起来再报告。
  waited=0
  until launchctl print "$LABEL" 2>/dev/null | grep -q '^[[:space:]]*state = running'; do
    [ "$waited" -lt 20 ] || fail "hzd 已加载但 10 秒内未进入运行状态。查看状态：sudo launchctl print ${LABEL}；查看日志：sudo tail -n 50 /Library/Logs/hzd.log"
    sleep 0.5
    waited=$((waited + 1))
  done
  echo "已启动 hzd 并设置开机自启（launchd）"
fi

echo ""
echo "安装完成，运行 hz up 加入 HzNet"
echo "（带 Auth Key：hz up --auth-key <Key>；缺省走交互式登录）"
