import Foundation

/// 到 hzd 的连接态（#85）。
public enum ConnectionState: Equatable, Sendable {
    /// 已连上（订阅活跃）。关联值为当前重连退避秒数——断开期间展示。
    case connected
    case reconnecting(afterSeconds: Int)

    public var isConnected: Bool { self == .connected }
}

/// `hz up` 的两种结局（#87）。
public enum UpOutcome: Equatable, Sendable {
    /// 已注册（新注册或恢复数据面）。
    case registered
    /// 未携带凭据时进入交互式登录：一次性 login_url（浏览器打开后轮询）。
    case loginStarted(url: String)
}

/// 后端访问协议（ADR-0010 / #85）：v0.4 唯一实现是 UDS JSON-lines 客户端
/// （`UDSBackend`）；测试与 SwiftUI 预览用 `FakeBackend`。为将来的
/// Network Extension 后端留缝——协议不暴露 socket 细节。
public protocol HzdBackend: AnyObject, Sendable {
    /// 订阅流（subscribe）：产出 (连接态, 最新快照)。hzd 未运行时快照为
    /// nil；断开后按 1s→2s→…→30s 退避重连，永不结束（App 生命周期内）。
    func events() -> AsyncStream<(connection: ConnectionState, snapshot: StatusSnapshot?)>

    /// 恢复 / 注册：带 coord 时优先使用；不带凭据走交互式登录（返回
    /// login_url）。邀请码走 `join(invite:coord:)`。
    func up(coord: String?) async throws -> UpOutcome
    /// 邀请码加入（成员档路径）：成功返回授予的 Node Name
    /// （hzd up(invite) 的应答是 RegisteredInfo 身份，非完整快照）。
    func join(invite: String, coord: String?) async throws -> String
    func down() async throws
    /// 交互式登录轮询（#87 引导窗）。
    func loginPoll() async throws -> LoginProgress
    /// 脱敏诊断（#84 / #90）。
    func diagnostics() async throws -> DiagnosticsReport
}

/// IPC 错误：hzd 返回的 `{"id":n,"error":"..."}` 或传输层失败。
public struct IpcError: Error, Equatable, Sendable, CustomStringConvertible {
    public var message: String
    public init(message: String) { self.message = message }
    public var description: String { message }
}
