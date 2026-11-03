// swift-tools-version: 5.9
// v0.4 macOS Client App（ADR-0010）。Kit 承载全部可测逻辑（快照模型、
// 六态判定、后端、引导、深链、通知、诊断导出）；App target 只是菜单栏壳。
// 平台 macOS 13+（MenuBarExtra 要求），arm64（规格 §9 不做 Intel）。
import PackageDescription

let package = Package(
    name: "HzNetClient",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "HzNetClientKit",
            path: "Sources/HzNetClientKit"
        ),
        .executableTarget(
            name: "HzNetClientApp",
            dependencies: ["HzNetClientKit"],
            path: "Sources/HzNetClientApp"
        ),
        // CLT（无完整 Xcode）跑不了 XCTest/Swift Testing 宏：测试是普通
        // 可执行 target，自带极简断言（HzTest），`swift run HzNetClientKitTests`
        // 退出码即结果；CI 与本机同一条命令。
        .executableTarget(
            name: "HzNetClientKitTests",
            dependencies: ["HzNetClientKit"],
            path: "Tests/HzNetClientKitTests"
        ),
    ]
)
