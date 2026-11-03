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
        versionName = (project.findProperty("hznetVersion") as String?) ?: "0.0.0"
        versionCode = versionName.split('.').let { parts ->
            (parts[0].toInt() * 1_000_000) + (parts[1].toInt() * 1_000) + parts[2].toInt()
        }
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
            // release 签名由 CI 注入（#102：keystore 在 GitHub Secrets）。
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

    applicationVariants.all {
        val variant = this
        val isRelease = variant.buildType.name == "release"
        val targets = if (isRelease) listOf("arm64-v8a") else listOf("arm64-v8a", "x86_64")
        val buildNative by tasks.registering(Exec::class) {
            workingDir(repoRoot)
            commandLine(
                listOf("cargo", "ndk") +
                    targets.flatMap { listOf("-t", it) } +
                    listOf("build", "-p", "hz-android") +
                    if (isRelease) listOf("--release") else emptyList()
            )
        }
        val syncNative by tasks.registering(Sync::class) {
            dependsOn(buildNative)
            val src = repoRoot.resolve(if (isRelease) "target/release" else "target/debug")
            from(src) {
                include("**/libhz_android.so")
                eachFile {
                    val triple = file.relativeTo(src).pathSegments.first()
                    val abi = when (triple) {
                        "aarch64-linux-android" -> "arm64-v8a"
                        "x86_64-linux-android" -> "x86_64"
                        else -> null
                    }
                    if (abi != null) {
                        path = "$abi/${file.name}"
                    } else {
                        exclude()
                    }
                }
            }
            into(layout.buildDirectory.dir("jniLibs/${variant.name}"))
        }
        variant.preBuildProvider.configure { dependsOn(syncNative) }
        sourceSets.getByName(variant.name) {
            jniLibs.srcDir(layout.buildDirectory.dir("jniLibs/${variant.name}"))
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
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
