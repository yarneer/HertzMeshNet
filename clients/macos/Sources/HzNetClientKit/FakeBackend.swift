import Foundation

/// 假后端（#85/#86/#87/#89）：SwiftUI 预览与表驱动测试。脚本化回放事件，
/// 记录调用供断言。
public final class FakeBackend: HzdBackend, @unchecked Sendable {
    public private(set) var calls: [String] = []
    public private(set) var upCoords: [String?] = []
    public private(set) var joinInvites: [String] = []
    private let lock = NSLock()
    /// up / join / down / loginPoll / diagnostics 的可编程结果。
    public var upOutcome: UpOutcome = .registered
    public var upError: String?
    public var joinName: String = "mini"
    public var joinError: String?
    public var downError: String?
    public var loginPollResult: LoginProgress = .idle
    public var diagnosticsReport: DiagnosticsReport?

    var continuations: [AsyncStream<(connection: ConnectionState, snapshot: StatusSnapshot?)>.Continuation] = []
    /// 最近一次事件：新订阅建立时立即重放（与 UDSBackend「订阅即推一份」
    /// 语义一致，也消除 emit 先于订阅建立的竞态）。
    var latest: (connection: ConnectionState, snapshot: StatusSnapshot?)?

    public init() {}

    public func events() -> AsyncStream<(connection: ConnectionState, snapshot: StatusSnapshot?)> {
        AsyncStream { continuation in
            self.lock.lock()
            self.continuations.append(continuation)
            let latest = self.latest
            self.lock.unlock()
            if let latest {
                continuation.yield(latest)
            }
        }
    }

    /// 喂一条事件给全部消费者（并记为最新，供之后建立的订阅重放）。
    public func emit(_ event: (connection: ConnectionState, snapshot: StatusSnapshot?)) {
        lock.lock()
        latest = event
        let sinks = continuations
        lock.unlock()
        for continuation in sinks {
            continuation.yield(event)
        }
    }

    private func record(_ call: String) {
        lock.lock()
        calls.append(call)
        lock.unlock()
    }

    public func up(coord: String?) async throws -> UpOutcome {
        record("up")
        lock.withLock { upCoords.append(coord) }
        if let upError { throw IpcError(message: upError) }
        return upOutcome
    }

    public func join(invite: String, coord: String?) async throws -> String {
        record("join")
        lock.withLock { joinInvites.append(invite) }
        if let joinError { throw IpcError(message: joinError) }
        return joinName
    }

    public func down() async throws {
        record("down")
        if let downError { throw IpcError(message: downError) }
    }

    public func loginPoll() async throws -> LoginProgress {
        record("login_poll")
        return loginPollResult
    }

    public func diagnostics() async throws -> DiagnosticsReport {
        record("diagnostics")
        guard let diagnosticsReport else {
            throw IpcError(message: "测试未配置 diagnosticsReport")
        }
        return diagnosticsReport
    }
}
