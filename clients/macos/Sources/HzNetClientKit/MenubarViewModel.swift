import Combine
import Foundation

/// 菜单栏视图模型（#85/#86/#89）：订阅事件流，暴露连接态 / 快照 / 派生
/// 状态 / 对端行；通知引擎在同一循环里评估（#89）。
@MainActor
public final class MenubarViewModel: ObservableObject {
    public let backend: any HzdBackend
    @Published public private(set) var connection: ConnectionState = .reconnecting(afterSeconds: 1)
    @Published public private(set) var snapshot: StatusSnapshot?

    /// 打开外部 URL / 写剪贴板 / 发通知由 App 注入（保持 Kit 可测）。
    public var openURL: @MainActor (String) -> Void = { _ in }
    public var copyText: @MainActor (String) -> Void = { _ in }
    public var notify: @MainActor (AppNotification) -> Void = { _ in }

    /// 通知去重状态（#89）。
    private var notificationEngine = NotificationEngine()
    private var streamTask: Task<Void, Never>?

    public init(backend: any HzdBackend) {
        self.backend = backend
    }

    public var status: AppStatus {
        AppStatus.determine(connection: connection, snapshot: snapshot)
    }

    public var peerRows: [PeerRow] {
        PeerRow.rows(snapshot: snapshot)
    }

    /// 是否应弹出首次启动引导（#87）：从未注册（含 hzd 暂不可达时的未知
    /// 态不弹——等连上再说）。
    public var showsOnboarding: Bool {
        guard connection.isConnected else { return false }
        guard let snapshot else { return false }
        return !snapshot.registered && snapshot.expired != true
    }

    public func start() {
        guard streamTask == nil else { return }
        streamTask = Task { [weak self] in
            guard let self else { return }
            for await event in backend.events() {
                self.connection = event.connection
                self.snapshot = event.snapshot
                if event.connection.isConnected, let snapshot = event.snapshot {
                    // 四种系统通知的触发评估（#89）：到期 / VPN 冲突 / 版本过旧。
                    let pending = notificationEngine.evaluate(
                        snapshot: snapshot,
                        now: Date()
                    )
                    for notification in pending {
                        self.notify(notification)
                    }
                }
            }
        }
    }

    public func stop() {
        streamTask?.cancel()
        streamTask = nil
    }

    // MARK: - 菜单动作

    /// 开关（up / down）：按当前 Desired State 取反向。
    public func toggleConnection() async {
        let currentlyDown = snapshot?.desiredState == "down"
        do {
            if currentlyDown {
                _ = try await backend.up(coord: nil)
            } else {
                try await backend.down()
            }
        } catch {
            // 动作失败：菜单仍由下一份快照反映真实状态；错误以系统通知
            // 形式提示（避免菜单栏弹窗打断）。
            notify(.actionFailed(message: "\(error)"))
        }
    }

    public func copyNodeAddress() {
        guard let snapshot else { return }
        let text = [snapshot.ipv4, snapshot.ipv6]
            .compactMap { $0 }
            .joined(separator: " / ")
        guard !text.isEmpty else { return }
        copyText(text)
    }

    public func copyPeerDomain(_ row: PeerRow) {
        guard let domain = row.domain else { return }
        copyText(domain)
    }

    /// 1 天到期通知的「重新登录」（#89）：走浏览器登录续期。
    public func relogin() async {
        do {
            if case .loginStarted(let url) = try await backend.up(coord: nil) {
                openURL(url)
            }
        } catch {
            notify(.actionFailed(message: "重新登录失败：\(error)"))
        }
    }
}
