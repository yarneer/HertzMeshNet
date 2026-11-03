// hznet Android Client App（#99）：Gradle 任务先 cargo ndk 构建 libhz_android.so
// 再打进 APK。versionName 与 workspace version 一致，versionCode 由版本号
// 推导且单调递增（#102 详述）。
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
