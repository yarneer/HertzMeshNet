# Android 真机冒烟测试（v0.4 / #103）

覆盖 [android-client-spec](android-client-spec.md) §13 全部验收项。每条给出
前置、步骤与判定；全部通过后才打 `v0.4.0` tag。测试机：一台未装过 HzNet 的
Android 9+ arm64 手机；辅助机：一台已加入 HzNet 的 Linux Node（如云主机）。

准备：

- coord 配置了 `--public-relay-addr` / `--public-stun-addr`（部署模板已带）；
- release APK 放在 coord 分发目录 `dist/android-arm64/hznet.apk`（开发验证
  可用 CI 的 debug APK：`gradle assembleDebug`）；
- Admin 准备一个邀请码（`hz invite create`）与浏览器登录账号。

## 1. 安装与加入（§13-1）

1. 手机浏览器打开 `https://coord.<域名>/dl/android-arm64/hznet.apk` 下载并
   安装（允许未知来源）；
2. App 引导页确认 coord 地址与 Node Name（预填机型名）；
3. 选"浏览器登录"完成组织登录（或输入邀请码）；
4. 授权一次 VPN。

✅ 判定：主界面显示"已连接"与本机 Node Address；在 Linux Node 上
`hz ping <手机 Node Name>` 通；手机上 `ping <linux Node Address>` 通、
`ping <name>.hznet.internal` 解析并通（可用任意终端 App / 浏览器访问 Linux
Node 上的内网 Web 验证名字解析）。

## 2. 其他 App 不受影响（§13-2）

✅ 判定：HzNet 连接期间，手机浏览器访问公网站点正常、App Store / 微信等
DNS 解析正常（VpnService 只路由 HzNet 网段；DNS 转发模式负责后缀外解析）。

## 3. 重启保持 Desired State（§13-3）

1. 关闭连接（App 开关 off）→ 重启手机；
2. 打开 App（不点连接）→ 重启一次（保持 up）。

✅ 判定：down 状态重启后仍断开；up 状态重启后自动连接（前台服务与常驻
通知恢复）。

## 4. 被其他 VPN 抢占（§13-4）

1. HzNet 连接中，打开任意其他 VPN App 并连接；
2. 回到 HzNet App。

✅ 判定：系统断开 HzNet（onRevoke）；App 显示"被其他 VPN 接管"并收到通知；
HzNet 不与对方争抢。断开另一个 VPN 后可重新连上 HzNet。

## 5. Wi-Fi ↔ 蜂窝切换（§13-5）

1. HzNet 连接中（对端显示 Direct 或 Relayed）；
2. 关闭 Wi-Fi 走蜂窝 → 开一条到 Linux Node 的持续 ping（终端 App）；
3. 30 秒内观察。

✅ 判定：切换后 30 秒内 ping 恢复（引擎经 onNetworkChanged 重绑并重采
Endpoint）；主界面对端状态最终回到 Direct/Relayed 的稳定值。

## 6. 入站 Policy（§13-6）

1. 手机上起一个 HTTP 服务（任意端口，如 8080）；
2. 在 coord 的 Policy 里允许该端口的入站（如 `to = "user:<手机归属>"`）；
3. Linux Node 上 `curl http://<手机 Node Address>:8080`；
4. 改 Policy 拒绝该端口，等 Map 推送后重试。

✅ 判定：允许时通、拒绝时不通（Policy 在手机端入方向执行）。

## 7. 到期通知（§13-7）

用短 TTL 邀请（`--node-ttl-days` 最小值或测试 coord 的短 TTL 通道）注册。

✅ 判定：到期前 3 天、1 天各收到一次通知；1 天档点开直达重新登录流程，
重新登录后续期、身份不变。

## 8. 诊断包脱敏（§13-8）

1. 期间做过：输入邀请码、浏览器登录（日志含 token）；
2. App → "导出诊断包" → 经分享面板发给自己；
3. 解开 zip 检查 `diagnostics.json` / `diagnostics.log`。

✅ 判定：不含私钥（PEM / 长十六进制）、Auth Key（`hznet.…`）、邀请码
（`HZ-XXXX-XXXX`）、登录 token（`/oidc/start/…`）；Node Name / Address /
Endpoint 保留。

## 9. App 内升级（§13-9）

1. 用旧版本 APK（如 0.4.0-debug）加入；
2. coord 分发目录换上新版 APK（manifest 的 version 更高）；
3. 等 App 每日检查（或设置页"检查更新"）→ 确认升级。

✅ 判定：升级后 Node Name 与 Node Address 不变；sha256 校验失败的包被丢弃
并提示（可用改坏 manifest 的 sha256 验证一次）。

## 10. Seam A/B（§13-10）

✅ 判定：`cargo test --all`（Linux / macOS CI）全绿；`clients/fixtures/`
重新生成无 diff。
