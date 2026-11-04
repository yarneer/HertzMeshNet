# HzNet Android Client App（v0.4，#99–#102）

组织内部 APK 分发（不上 Google Play）：从 `https://coord.<域名>/dl/android-arm64/hznet.apk`
下载安装。minSdk 28（Android 9）；release 仅 arm64-v8a，debug 另加 x86_64 供模拟器。

## 构建（debug）

需要：JDK 17、Android SDK（34）、NDK、Rust（`rustup target add
aarch64-linux-android x86_64-linux-android`）、`cargo install cargo-ndk`。

Gradle 任务会先 `cargo ndk` 构建 `libhz_android.so`（workspace 的
`crates/hz-android`）再打进 APK：

```sh
cd clients/android
gradle assembleDebug          # 或 CI；wrapper 见下
adb install app/build/outputs/apk/debug/app-debug.apk
```

**Gradle wrapper**：已携带（`gradlew` + 8.11.1 wrapper jar）。CI 用
`gradle/actions/setup-gradle` 指定发行版直接跑 `gradle`（不依赖 wrapper），
本机 `./gradlew` 亦可。

## 测试

- Rust：`cargo test -p hz-android`（成员档闸门、配置档位、环形日志脱敏）
  与 `cargo test -p hz-engine`（引擎 / DNS 转发）在 host 上跑。
- Kotlin：`gradle testDebugUnitTest`（解码 `clients/fixtures/` 全部
  fixture，#99 契约测试）。
- 真机冒烟：`docs/android-smoke-test.md`（#103）。

## 结构

```
app/src/main/java/dev/hznet/android/
  engine/  EngineBridge（JNI 绑定）、HzNetPlatform（establish/protect 回调）
  vpn/     HzNetVpnService（前台服务 / onRevoke / 网络回调）、BootReceiver
  ui/      MainActivity（#99 极简界面；#100 Compose 全量）、AppModel
```

密钥安全：`allowBackup=false` 且 `dataExtractionRules` 排除
`filesDir/hznet`（私钥文件是唯一事实源，不进云备份 / 设备迁移）。
