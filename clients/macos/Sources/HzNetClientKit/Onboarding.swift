import Combine
import Foundation

/// 引导窗视图模型（#87）：coord 地址校验 + 浏览器登录（up 拿 login_url →
/// 打开浏览器 → 轮询 login_poll）+ 邀请码两条路径。GUI 不提供 Auth Key
/// 输入（管理档）。
@MainActor
public final class OnboardingViewModel: ObservableObject {
    /// 预填默认值：与 hz-core `DEFAULT_COORD_ADDR` 同一常量。
    public static let defaultCoord = "https://coord.hznet.internal:443"

    @Published public var coordText: String = OnboardingViewModel.defaultCoord
    @Published public var phase: Phase = .idle

    public enum Phase: Equatable {
        case idle
        /// 浏览器登录：等用户在浏览器完成（轮询中）。
        case waitingBrowser
        /// 邀请码提交中。
        case joining
        /// 登录 / 加入完成。
        case done
        case failed(String)
    }

    /// 打开浏览器由 App 注入（NSWorkspace）；测试注入记录闭包。
    public var openURL: @MainActor (String) -> Void = { _ in }

    /// coord 格式校验（提交前）：http/https + 非空 host。https 之外允许
    /// http 是为本地开发 coord；与深链的 https-only 不同（深链来自外部）。
    public var coordValid: Bool {
        OnboardingViewModel.validCoord(coordText)
    }

    public static func validCoord(_ text: String) -> Bool {
        guard let url = URL(string: text.trimmingCharacters(in: .whitespaces)),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = url.host, !host.isEmpty
        else { return false }
        return true
    }

    private var effectiveCoord: String? {
        let trimmed = coordText.trimmingCharacters(in: .whitespaces)
        return trimmed == Self.defaultCoord ? nil : trimmed
    }

    /// 浏览器登录路径：up（无凭据）→ login_url → 系统浏览器 → 轮询。
    public func startBrowserLogin(backend: any HzdBackend) async {
        guard coordValid else {
            phase = .failed("Coordination Server 地址无效（应为 http(s)://host[:port]）")
            return
        }
        phase = .waitingBrowser
        do {
            let outcome = try await backend.up(coord: effectiveCoord)
            guard case .loginStarted(let url) = outcome else {
                // 已注册（例如别的窗口刚加入）：直接完成。
                phase = .done
                return
            }
            openURL(url)
            await pollLogin(backend: backend)
        } catch {
            phase = .failed("连接 Coordination Server 失败：\(error)")
        }
    }

    /// 轮询 login_poll 直到终态；链接过期 / 失败进入 failed（可重试）。
    private func pollLogin(backend: any HzdBackend) async {
        while phase == .waitingBrowser {
            do {
                switch try await backend.loginPoll() {
                case .idle, .pending:
                    try? await Task.sleep(for: .seconds(1))
                case .completed:
                    phase = .done
                    return
                case .failed(let reason):
                    phase = .failed(reason)
                    return
                }
            } catch {
                // 轮询本身失败（hzd 重启等）：按 pending 处理继续等。
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// 邀请码路径：直接 up；失败显示 coord 返回的原因。
    public func join(invite: String, backend: any HzdBackend) async {
        let code = invite.trimmingCharacters(in: .whitespaces)
        guard !code.isEmpty else {
            phase = .failed("请输入邀请码")
            return
        }
        guard coordValid else {
            phase = .failed("Coordination Server 地址无效（应为 http(s)://host[:port]）")
            return
        }
        phase = .joining
        do {
            _ = try await backend.join(invite: code, coord: effectiveCoord)
            phase = .done
        } catch {
            phase = .failed("\(error)")
        }
    }

    /// 失败后重试：回到输入态。
    public func reset() {
        phase = .idle
    }
}
