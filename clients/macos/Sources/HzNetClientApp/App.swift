import AppKit
import SwiftUI
import UserNotifications

import HzNetClientKit

/// v0.4 macOS Client App（ADR-0010）：SwiftUI MenuBarExtra 菜单栏壳。
/// 全部逻辑在 HzNetClientKit（可测）；本文件只做装配与系统交互
/// （剪贴板 / 浏览器 / 通知 / 保存面板 / 深链）。
@main
struct HzNetClientApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @State private var model: MenubarViewModel
    @State private var onboarding = OnboardingViewModel()
    @State private var onboardingShown = false
    @State private var exportError: String?

    init() {
        let backend = UDSBackend()
        let model = MenubarViewModel(backend: backend)
        // 系统集成接线（#86/#87/#89）：Kit 只定义注入点，App 提供实现。
        model.copyText = { text in
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }
        model.openURL = { url in
            if let url = URL(string: url) {
                NSWorkspace.shared.open(url)
            }
        }
        model.notify = { notification in
            let content = UNMutableNotificationContent()
            content.title = notification.title
            content.body = notification.body
            // 1 天到期通知带「重新登录」按钮（#89）。
            if case .expiresIn1Day = notification {
                content.categoryIdentifier = "HzNetExpiry"
            }
            let request = UNNotificationRequest(
                identifier: notification.identifier,
                content: content,
                trigger: nil
            )
            UNUserNotificationCenter.current().add(request)
        }
        _model = State(initialValue: model)

        // 深链与「重新登录」动作（#88/#89）。
        Self.pendingModel = model
        Self.pendingOnboarding = onboarding
        AppDelegate.onDeepLink = { url in
            Self.joinFlow(
                url,
                model: Self.pendingModel,
                registeredCoord: Self.pendingModel?.snapshot?.coordAddr
            )
        }
        AppDelegate.onRelogin = {
            Task { @MainActor in await Self.pendingModel?.relogin() }
        }
    }

    /// App struct 会被 SwiftUI 重建：深链回调经此持有当前视图模型与引导模型。
    @MainActor nonisolated(unsafe) static var pendingModel: MenubarViewModel?
    @MainActor nonisolated(unsafe) static var pendingOnboarding: OnboardingViewModel?

    /// 深链处理需要访问 @State 的 model；用静态暂存绕过 App struct 重建。
    nonisolated(unsafe) static var currentHandler: (@MainActor (URL, MenubarViewModel?) -> Void)? = { _, _ in }

    var body: some Scene {
        MenuBarExtra {
            MenuContent(
                model: model,
                exportError: exportError,
                onExport: exportDiagnostics,
                onQuit: { NSApp.terminate(nil) }
            )
            .onAppear { model.start() }
        } label: {
            Image(systemName: model.status.symbolName)
        }
        .menuBarExtraStyle(.menu)

        // 首次启动引导（#87）：未注册时打开；done 或已注册时收起。
        WindowGroup("加入 HzNet", id: "onboarding") {
            OnboardingView(model: onboarding, backend: model.backend)
                .onChange(of: model.showsOnboarding) { _, shows in
                    guard shows, !onboardingShown else { return }
                    onboardingShown = true
                    openWindow(id: "onboarding")
                }
                .onChange(of: onboarding.phase) { _, phase in
                    if phase == .done {
                        onboardingShown = false
                        NSApp.keyWindow?.close()
                    }
                }
        }
        .windowResizability(.contentSize)
    }

    // MARK: - 深链（#88）

    /// 待确认的 join 请求（校验通过后由确认框展示域名）。
    struct JoinPrompt: Identifiable {
        let id = UUID()
        var coord: URL
        var invite: String
        var title = "加入 HzNet 网络"
        var message: String
    }

    /// 深链校验 + 弹确认框；确认后走邀请码路径。
    func handleDeepLink(_ url: URL) {
        switch DeepLink.parse(url: url, registeredCoord: model.snapshot?.coordAddr) {
        case .valid(let coord, let invite):
            joinPrompt = JoinPrompt(
                coord: coord,
                invite: invite,
                message: DeepLink.confirmMessage(coord: coord, invite: invite)
            )
        case .alreadyJoined(let coord):
            joinPrompt = JoinPrompt(
                coord: coord,
                invite: "",
                title: "已加入该网络",
                message: DeepLink.alreadyJoinedMessage(coord: coord)
            )
        case .invalid(let reason):
            joinPrompt = JoinPrompt(
                coord: URL(string: "https://invalid.example")!,
                invite: "",
                title: "无法加入",
                message: reason
            )
        }
    }

    /// 确认框执行：仅 valid 且用户点「加入」才走邀请码路径。
    func confirmJoin(_ prompt: JoinPrompt) {
        guard !prompt.invite.isEmpty else { return }
        Task { @MainActor in
            onboarding.join(invite: prompt.invite, backend: model.backend)
        }
    }

    // MARK: - 导出诊断包（#90）

    func exportDiagnostics() {
        Task { @MainActor in
            do {
                let report = try await model.backend.diagnostics()
                let data = try DiagnosticsExport.makeArchive(report: report)
                let panel = NSSavePanel()
                panel.nameFieldStringValue = DiagnosticsExport.defaultFileName(
                    nodeName: report.status.name ?? "node",
                    now: Date()
                )
                guard panel.runModal() == .OK, let url = panel.url else { return }
                try data.write(to: url)
                exportError = nil
            } catch {
                exportError = "导出诊断包失败：\(error)"
            }
        }
    }
}

/// 系统集成层：通知授权 + relogin 动作注册 + 深链入口。
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    static var onDeepLink: (@MainActor (URL) -> Void)?
    static var onRelogin: (@MainActor () -> Void)?

    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
        // 静默失败：拒绝授权时通知 simply 不出现（#89 验收只要求请求）。
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
        // 「重新登录」按钮（#89）：1 天到期通知的动作。
        let relogin = UNNotificationAction(
            identifier: "relogin",
            title: "重新登录",
            options: [.activationMode(.foreground)]
        )
        let category = UNNotificationCategory(
            identifier: "HzNetExpiry",
            actions: [relogin],
            intentIdentifiers: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    /// App 未运行时点击深链由 macOS 冷启动并回调这里（Info.plist 注册
    /// CFBundleURLTypes：hznet scheme）。
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls where url.scheme?.lowercased() == "hznet" {
            let handler = Self.onDeepLink
            Task { @MainActor in handler?(url) }
        }
    }

    /// 通知动作（#89）：1 天到期的「重新登录」按钮。
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        if response.actionIdentifier == "relogin" {
            let handler = Self.onRelogin
            Task { @MainActor in handler?() }
        }
        completionHandler()
    }
}

// MARK: - 菜单内容（#86）

struct MenuContent: View {
    let model: MenubarViewModel
    var exportError: String?
    let onExport: () -> Void
    let onQuit: () -> Void

    var body: some View {
        // 状态行 + 开关。
        Text(model.status.title)
        Toggle(
            model.snapshot?.desiredState == "down" ? "连接（hz up）" : "断开（hz down）",
            isOn: Binding(
                get: { model.snapshot.map { $0.desiredState != "down" } ?? false },
                set: { _ in Task { await model.toggleConnection() } }
            )
        )
        Divider()
        if let name = model.snapshot?.name {
            // 本机 Node Name / Node Address（点击复制，#86）。
            Button("本机：\(name)（\(model.snapshot?.ipv4 ?? "")）复制地址") {
                model.copyNodeAddress()
            }
            Divider()
            if model.peerRows.isEmpty {
                Text("对端：无")
            } else {
                Text("对端：")
                ForEach(model.peerRows) { row in
                    Button(menuTitle(row)) {
                        model.copyPeerDomain(row)
                    }
                }
            }
            Divider()
        }
        Button("导出诊断包…") { onExport() }
        .disabled(!model.connection.isConnected)
        if let exportError {
            Text(exportError).foregroundStyle(.red)
        }
        Button("退出") { onQuit() }
    }

    /// 对端行：名字 · 路径（原因）· 延迟（最近握手距今）。
    private func menuTitle(_ row: PeerRow) -> String {
        let latency = row.handshakeSecs.map { "\($0)s" } ?? "—"
        return "\(row.name) · \(row.pathText) · \(latency)"
    }
}

// MARK: - 引导窗（#87）

struct OnboardingView: View {
    @State var model: OnboardingViewModel
    let backend: any HzdBackend

    var body: some View {
        Form {
            Section("Coordination Server") {
                TextField("地址", text: $model.coordText)
                if !model.coordValid {
                    Text("地址应为 http(s)://host[:port]")
                        .foregroundStyle(.red)
                }
            }
            switch model.phase {
            case .waitingBrowser:
                Section {
                    Text("已打开浏览器，请完成登录…")
                    ProgressView().controlSize(.small)
                }
            case .joining:
                Section { ProgressView().controlSize(.small) }
            case .done:
                Section { Text("已加入 HzNet，窗口将自动关闭。") }
            case .failed(let reason):
                Section {
                    Text(reason).foregroundStyle(.red)
                    Button("重试") { model.reset() }
                }
            case .idle:
                Section("接入方式") {
                    Button("浏览器登录") {
                        Task { await model.startBrowserLogin(backend: backend) }
                    }
                    InviteField(model: model, backend: backend)
                }
            }
        }
        .frame(minWidth: 420, minHeight: 240)
    }
}

struct InviteField: View {
    @State var model: OnboardingViewModel
    let backend: any HzdBackend
    @State private var invite = ""
    @FocusState private var focused: Bool

    var body: some View {
        HStack {
            TextField("邀请码（HZ-XXXX-XXXX）", text: $invite)
                .focused($focused)
            Button("加入") {
                Task { await model.join(invite: invite, backend: backend) }
            }
            .disabled(invite.trimmingCharacters(in: .whitespaces).isEmpty || !model.coordValid)
        }
    }
}
