#!/bin/sh
# HzNet 一条命令安装（FR-13）。hz-coord 在 serve 时把
# @@HZNET_COORD_URL@@（HTTP 分发面）与 @@HZNET_COORD_GRPC_ADDR@@（gRPC 面）
# 替换成 --public-url / --public-grpc-addr 的值；直接运行仓库原件时占位符
# 未替换，靠 HZNET_COORD_URL / HZNET_COORD_ADDR 环境变量兜底。
# Relay：HZNET_RELAY_ADDR 优先；否则 Coordination Server 主机名是 coord.<域名>
# 时按 ADR-0004 写成 https://relay.<域名>。已有 HZD_RELAY_ADDR 重跑不覆盖。
set -eu

fail() { echo "安装失败：$*" >&2; exit 1; }

# 打印本次要写入的 Relay URL。空字符串表示推导不出、也不新写。
# 显式 HZNET_RELAY_ADDR 不是 http(s) URL 或含空白时返回 1。
resolve_relay_addr() {
  coord=$1
  explicit=${HZNET_RELAY_ADDR:-}
  case "$explicit" in
    "") ;;
    http://*|https://*)
      case "$explicit" in
        *[[:space:]]*)
          echo "HZNET_RELAY_ADDR 含空白" >&2
          return 1
          ;;
      esac
      printf '%s\n' "$explicit"
      return 0
      ;;
    *)
      echo "HZNET_RELAY_ADDR 必须是 http:// 或 https:// URL" >&2
      return 1
      ;;
  esac
  case "$coord" in
    http://*|https://*) ;;
    *) return 0 ;;
  esac
  rest=${coord#*://}
  rest=${rest%%/*}
  host=${rest%%:*}
  # coord.example.com 才推导；coord、IP、单标签主机名留给显式 HZNET_RELAY_ADDR。
  case "$host" in
    coord.*.*)
      printf 'https://relay.%s\n' "${host#coord.}"
      ;;
  esac
}

# 写出节点环境文件：HZD_COORD_ADDR 换成本次的值，其余行原样保留。
# 尚无 HZD_RELAY_ADDR 且 relay 非空时追加；已有则一行不动。
write_hzd_env() {
  dest=$1
  existing=$2
  grpc=$3
  relay=$4
  {
    printf 'HZD_COORD_ADDR=%s\n' "$grpc"
    if [ -n "$existing" ] && [ -f "$existing" ]; then
      grep -Ev '^[[:space:]]*(export[[:space:]]+)?HZD_COORD_ADDR=' "$existing" || true
    fi
  } > "$dest"
  if ! grep -Eq '^[[:space:]]*(export[[:space:]]+)?HZD_RELAY_ADDR=' "$dest"; then
    if [ -n "$relay" ]; then
      printf 'HZD_RELAY_ADDR=%s\n' "$relay" >> "$dest"
    fi
  fi
}

self_check() {
  unset HZNET_RELAY_ADDR || true
  got=$(resolve_relay_addr "https://coord.example.com")
  [ "$got" = "https://relay.example.com" ] || fail "推导主机名失败：[$got]"
  got=$(resolve_relay_addr "https://coord.example.com:443")
  [ "$got" = "https://relay.example.com" ] || fail "推导时未去掉端口：[$got]"
  got=$(resolve_relay_addr "https://coord.example.com/dl")
  [ "$got" = "https://relay.example.com" ] || fail "推导时未去掉路径：[$got]"
  got=$(resolve_relay_addr "http://coord:9443")
  [ -z "$got" ] || fail "裸主机名不应推导 Relay：[$got]"
  got=$(resolve_relay_addr "http://10.0.0.1:50051")
  [ -z "$got" ] || fail "IP 不应推导 Relay：[$got]"
  HZNET_RELAY_ADDR=https://relay.custom.test:8443
  got=$(resolve_relay_addr "https://coord.example.com")
  [ "$got" = "https://relay.custom.test:8443" ] || fail "显式 HZNET_RELAY_ADDR 未优先：[$got]"
  HZNET_RELAY_ADDR='https://bad host'
  if resolve_relay_addr "https://coord.example.com" >/dev/null 2>&1; then
    fail "含空白的 HZNET_RELAY_ADDR 应被拒绝"
  fi
  unset HZNET_RELAY_ADDR || true

  tmp=$(mktemp -d)
  trap 'rm -rf '"$tmp" EXIT
  printf '%s\n' 'HZD_COORD_ADDR=http://old:1' 'HZD_RELAY_ADDR=https://relay.custom:9' 'HZD_STUN_ADDR=1.2.3.4:3478' > "$tmp/old"
  write_hzd_env "$tmp/new" "$tmp/old" "https://coord.example.com" "https://relay.example.com"
  grep -qx 'HZD_COORD_ADDR=https://coord.example.com' "$tmp/new" || fail "未更新 HZD_COORD_ADDR"
  grep -qx 'HZD_RELAY_ADDR=https://relay.custom:9' "$tmp/new" || fail "已有 HZD_RELAY_ADDR 被覆盖"
  grep -qx 'HZD_STUN_ADDR=1.2.3.4:3478' "$tmp/new" || fail "其他变量丢失"
  [ "$(grep -c '^HZD_COORD_ADDR=' "$tmp/new")" = 1 ] || fail "HZD_COORD_ADDR 不唯一"
  [ "$(grep -c '^HZD_RELAY_ADDR=' "$tmp/new")" = 1 ] || fail "HZD_RELAY_ADDR 重复"

  write_hzd_env "$tmp/fresh" "" "https://coord.example.com" "https://relay.example.com"
  grep -qx 'HZD_COORD_ADDR=https://coord.example.com' "$tmp/fresh" || fail "新文件缺 HZD_COORD_ADDR"
  grep -qx 'HZD_RELAY_ADDR=https://relay.example.com' "$tmp/fresh" || fail "新文件未写入推导的 Relay"

  write_hzd_env "$tmp/norelay" "" "http://coord:9443" ""
  [ "$(grep -c '^HZD_RELAY_ADDR=' "$tmp/norelay" || true)" = 0 ] || fail "推导不出时不应写 HZD_RELAY_ADDR"

  printf '%s\n' 'HZD_COORD_ADDR=http://old' 'HZD_STUN_ADDR=x' > "$tmp/nor"
  write_hzd_env "$tmp/filled" "$tmp/nor" "https://coord.example.com" "https://relay.example.com"
  grep -qx 'HZD_RELAY_ADDR=https://relay.example.com' "$tmp/filled" || fail "缺 Relay 时未补上"
  grep -qx 'HZD_STUN_ADDR=x' "$tmp/filled" || fail "补 Relay 时丢掉了其他变量"

  printf '%s\n' 'export HZD_RELAY_ADDR=https://keep.example' > "$tmp/exp"
  write_hzd_env "$tmp/expout" "$tmp/exp" "https://coord.example.com" "https://relay.example.com"
  grep -qx 'export HZD_RELAY_ADDR=https://keep.example' "$tmp/expout" || fail "export 形式的 HZD_RELAY_ADDR 未保留"
  [ "$(grep -c 'HZD_RELAY_ADDR=' "$tmp/expout")" = 1 ] || fail "export 形式的 Relay 被再写一行"
  echo "self-check: PASS"
}

if [ "${1:-}" = "--self-check" ]; then
  self_check
  exit 0
fi

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
RELAY_ADDR=$(resolve_relay_addr "$GRPC_ADDR") || fail "HZNET_RELAY_ADDR 无效：需要 http:// 或 https:// URL，且不能含空白"

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
  # 升级时 HZD_COORD_ADDR 换成本次的值；已有 HZD_RELAY_ADDR 保留，没有且本次
  # 能确定 Relay 地址才追加（安装手册第 6 节）。写回用 cat > 而非 mv，保留原文件属主与权限。
  ENV_FILE=/etc/default/hzd
  had_relay=0
  if [ -f "$ENV_FILE" ] && grep -Eq '^[[:space:]]*(export[[:space:]]+)?HZD_RELAY_ADDR=' "$ENV_FILE"; then
    had_relay=1
  fi
  write_hzd_env "$STAGE/hzd.env" "$ENV_FILE" "$GRPC_ADDR" "$RELAY_ADDR"
  cat "$STAGE/hzd.env" > "$ENV_FILE"
  if [ "$had_relay" = 1 ]; then
    echo "已保留已有的 HZD_RELAY_ADDR"
  elif [ -n "$RELAY_ADDR" ]; then
    echo "已写入 HZD_RELAY_ADDR=${RELAY_ADDR}"
  fi
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
  # hz 客户端也读 HZD_COORD_ADDR；登录 shell 注入后 `hz up` 不必带 --coord。
  # Relay 只给 hzd（EnvironmentFile），不进登录 shell。
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
  # HZD_RELAY_ADDR 不放进模板：PlistBuddy Merge 同名键保留模板值，放进去会盖掉用户改过的地址。
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
  had_relay=0
  if [ -f "$PLIST" ] && /usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:HZD_RELAY_ADDR' "$PLIST" >/dev/null 2>&1; then
    had_relay=1
  fi
  # 升级时保留旧 plist EnvironmentVariables 里用户加的键（改过的 HZD_RELAY_ADDR、
  # HZD_STUN_ADDR、HZD_BOOTSTRAP_DNS 等，见安装手册第 6 节）。Merge 遇到同名键
  # 跳过并保留新模板里的值，所以 HZD_COORD_ADDR 取本次的值、其余键原样带过来；
  # 值整体以 plist 搬运，路径里的空格与引号不经 shell 转义。
  if [ -f "$PLIST" ] && plutil -extract EnvironmentVariables xml1 -o "$STAGE/env.plist" "$PLIST" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Merge $STAGE/env.plist :EnvironmentVariables" "$STAGE/hzd.plist" >/dev/null \
      || fail "无法合并 $PLIST 中已有的环境变量；原文件未改动，请检查其 EnvironmentVariables 段"
    echo "已保留 $PLIST 中已有的环境变量（HZD_COORD_ADDR 更新为 ${GRPC_ADDR}）"
  fi
  if [ "$had_relay" = 1 ]; then
    echo "已保留已有的 HZD_RELAY_ADDR"
  elif [ -n "$RELAY_ADDR" ]; then
    /usr/libexec/PlistBuddy -c "Add :EnvironmentVariables:HZD_RELAY_ADDR string ${RELAY_ADDR}" "$STAGE/hzd.plist" \
      || fail "无法写入 HZD_RELAY_ADDR"
    echo "已写入 HZD_RELAY_ADDR=${RELAY_ADDR}"
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
