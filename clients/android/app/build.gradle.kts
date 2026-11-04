plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// ---- cargo ndk：先构建 libhz_android.so 再打进 APK（规格 §9）----
// 仓库根（clients/android 的上上级）；Gradle 任务与 CI 直接调 cargo ndk。
val repoRoot = rootProject.projectDir.parentFile.parentFile

android {
    namespace = "dev.hznet.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.hznet.android"
        // versionName 与 workspace version 一致；versionCode 由版本号推导
        // （major×1_000_000 + minor×1_000 + patch），单调递增（#102）。
        val hznetVersion = (project.findProperty("hznetVersion") as String?) ?: "0.0.0"
        versionName = hznetVersion
        versionCode = hznetVersion.split('.').let { parts ->
            (parts[0].toInt() * 1_000_000) + (parts[1].toInt() * 1_000) + parts[2].toInt()
        }.coerceAtLeast(1)
        minSdk = 28
        targetSdk = 34
        // debug 另加 x86_64 供模拟器（规格 §2）；release 仅 arm64-v8a。
        ndk {
            val isRelease = gradle.startParameter.taskNames.any {
                it.contains("release", ignoreCase = true)
            }
            abiFilters += if (isRelease) listOf("arm64-v8a") else listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // release 签名由 CI 注入（#102：keystore 在 GitHub Secrets，
            // 经 -PhznetKeystore* 传入；未提供时不签名）。
            val keystoreFile = project.findProperty("hznetKeystoreFile") as String?
            if (keystoreFile != null) {
                signingConfig = signingConfigs.create("release") {
                    storeFile = file(keystoreFile)
                    storePassword = project.findProperty("hznetKeystorePassword") as String
                    keyAlias = project.findProperty("hznetKeystoreAlias") as String
                    keyPassword = project.findProperty("hznetKeystoreKeyPassword") as String
                }
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    sourceSets {
        getByName("test") {
            // 契约 fixture（clients/fixtures/）作为测试资源（#99 CI：
            // Kotlin 解码全部 fixture）。
            assets.srcDir(rootProject.file("../fixtures"))
        }
    }
    testOptions {
        unitTests.all {
            it.systemProperty("hznet.fixtures.dir", rootProject.file("../fixtures").absolutePath)
        }
    }

    // 变体各自的 jniLibs 目录（debug 含 x86_64 供模拟器，release 仅 arm64-v8a）。
    sourceSets.getByName("debug") {
        jniLibs.srcDir(layout.buildDirectory.dir("jniLibs/debug"))
    }
    sourceSets.getByName("release") {
        jniLibs.srcDir(layout.buildDirectory.dir("jniLibs/release"))
    }
}

// ---- cargo ndk → .so → jniLibs（按变体）----
fun cargoNdkCommand(release: Boolean, targets: List<String>) = listOf("cargo", "ndk") +
    targets.flatMap { listOf("-t", it) } +
    listOf("build", "-p", "hz-android") +
    if (release) listOf("--release") else emptyList()

val buildNativeDebug by tasks.registering(Exec::class) {
    workingDir(repoRoot)
    commandLine(cargoNdkCommand(false, listOf("arm64-v8a", "x86_64")))
}

val buildNativeRelease by tasks.registering(Exec::class) {
    workingDir(repoRoot)
    commandLine(cargoNdkCommand(true, listOf("arm64-v8a")))
}

val syncNativeDebug by tasks.registering(Sync::class) {
    dependsOn(buildNativeDebug)
    from(repoRoot.resolve("target/aarch64-linux-android/debug")) {
        include("libhz_android.so")
        into("arm64-v8a")
    }
    from(repoRoot.resolve("target/x86_64-linux-android/debug")) {
        include("libhz_android.so")
        into("x86_64")
    }
    into(layout.buildDirectory.dir("jniLibs/debug"))
}

val syncNativeRelease by tasks.registering(Sync::class) {
    dependsOn(buildNativeRelease)
    from(repoRoot.resolve("target/aarch64-linux-android/release")) {
        include("libhz_android.so")
        into("arm64-v8a")
    }
    into(layout.buildDirectory.dir("jniLibs/release"))
}

// 只在对应变体构建时跑对应的原生任务。
tasks.matching { it.name == "mergeDebugJniLibFolders" }.configureEach { dependsOn(syncNativeDebug) }
tasks.matching { it.name == "mergeReleaseJniLibFolders" }.configureEach { dependsOn(syncNativeRelease) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.work)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    debugImplementation(libs.androidx.compose.ui.tooling)
    testImplementation(libs.junit)
    testImplementation(libs.org.json)
}
