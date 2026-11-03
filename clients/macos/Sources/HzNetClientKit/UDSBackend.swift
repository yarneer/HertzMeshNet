import Foundation
import Network

/// UDS JSON-lines 后端（#85）：hzd 的本地 IPC socket。
///
/// - 一问一答：连接 → 写一行请求 → 读一行响应 → 关闭（与 `hz` CLI 同构）。
/// - subscribe：长连接，逐行读快照；45 秒无任何一行视为断开（心跳应 15
///   秒一份），随后按 1s→2s→…→30s 指数退避重连，退避上限 30s。
public final class UDSBackend: HzdBackend, @unchecked Sendable {
    let socketPath: String
    /// 多消费者广播（App 主 UI + 通知各持一条流）。
    private var sinks: [UUID: AsyncStream<(connection: ConnectionState, snapshot: StatusSnapshot?)>.Continuation] = [:]
    private let lock = NSLock()
    private var reconnectTask: Task<Void, Never>?
    /// 单问一答的串行化：UDS 上每条连接独立，无需全局串行；这里只用于
    /// 防止重复启动订阅循环。
    private var streaming = false

    public init(socketPath: String) {
        self.socketPath = socketPath
    }

    public convenience init() {
        // 与 hzd 默认 socket 一致（HZD_SOCK_PATH 可覆盖；App 常规安装固定路径）。
        let path = ProcessInfo.processInfo.environment["HZD_SOCK_PATH"]
            ?? "/var/run/hzd.sock"
        self.init(socketPath: path)
    }

    // MARK: - 订阅流

    public func events() -> AsyncStream<(connection: ConnectionState, snapshot: StatusSnapshot?)> {
        let id = UUID()
        let stream = AsyncStream<(connection: ConnectionState, snapshot: StatusSnapshot?)> { continuation in
            self.lock.lock()
            self.sinks[id] = continuation
            let shouldStart = !self.streaming
            self.streaming = true
            self.lock.unlock()
            continuation.onTermination = { _ in
                self.lock.lock()
                self.sinks[id] = nil
                let empty = self.sinks.isEmpty
                if empty { self.streaming = false }
                self.lock.unlock()
                if empty {
                    self.reconnectTask?.cancel()
                    self.reconnectTask = nil
                }
            }
            if shouldStart {
                self.reconnectTask = Task { await self.runSubscription() }
            }
        }
        return stream
    }

    private func broadcast(_ event: (connection: ConnectionState, snapshot: StatusSnapshot?)) {
        lock.lock()
        let sinks = self.sinks
        lock.unlock()
        for continuation in sinks.values {
            continuation.yield(event)
        }
    }

    /// 订阅主循环：连接 → subscribe → 逐行推送 → 断开 → 退避重连。
    private func runSubscription() async {
        var backoff: Int = 1
        while !Task.isCancelled {
            do {
                try await withSubscriptionSession { snapshot in
                    self.broadcast((.connected, snapshot))
                    backoff = 1 // 收到首行即重置退避。
                }
                // 会话正常结束（服务端关闭）：按断开重连。
            } catch {
                // 连接失败 / 超时：同样退避。
            }
            guard !Task.isCancelled else { return }
            broadcast((.reconnecting(afterSeconds: backoff), nil))
            try? await Task.sleep(for: .seconds(backoff))
            backoff = min(backoff * 2, 30)
        }
    }

    /// 一条订阅会话：成功收到第一行前不改变对外状态（由调用方处理失败）。
    private func withSubscriptionSession(
        onSnapshot: @escaping (StatusSnapshot) -> Void
    ) async throws {
        let session = try await Session(socketPath: socketPath)
        let request = """
        {"id":1,"method":"subscribe","params":{}}
        """
        var firstLine: Data?
        try await session.exchange(request: request) { line in
            if firstLine == nil {
                firstLine = line
            }
            guard let snapshot = Self.decodeSnapshot(line) else { return }
            onSnapshot(snapshot)
        }
        guard firstLine != nil else {
            throw IpcError(message: "hzd 关闭了订阅连接而没有响应")
        }
    }

    static func decodeSnapshot(_ line: Data) -> StatusSnapshot? {
        struct Wire: Decodable {
            var id: Int?
            var result: StatusSnapshot?
            var error: String?
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: line) else { return nil }
        return wire.result
    }

    // MARK: - 一问一答

    public func up(coord: String?) async throws -> UpOutcome {
        var params: [String: String] = [:]
        if let coord, !coord.isEmpty { params["coord_addr"] = coord }
        let line = try await requestOne(method: "up", params: params)
        return try Self.decodeUpOutcome(line)
    }

    static func decodeUpOutcome(_ line: Data) throws -> UpOutcome {
        struct Wire: Decodable {
            var result: UpResultWire?
            var error: String?
        }
        struct UpResultWire: Decodable {
            var login_url: String?
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: line) else {
            throw IpcError(message: "无法解析 hzd 应答")
        }
        if let error = wire.error { throw IpcError(message: error) }
        if let url = wire.result?.login_url { return .loginStarted(url: url) }
        return .registered
    }

    public func join(invite: String, coord: String?) async throws -> String {
        var params: [String: String] = ["invite_code": invite]
        if let coord, !coord.isEmpty { params["coord_addr"] = coord }
        let line = try await requestOne(method: "up", params: params)
        struct Wire: Decodable {
            // hzd up(invite) 成功应答是 RegisteredInfo（node_id/name/ipv4/…）。
            var result: RegisteredInfoWire?
            var error: String?
        }
        struct RegisteredInfoWire: Decodable {
            var name: String?
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: line) else {
            throw IpcError(message: "无法解析 hzd 应答")
        }
        if let error = wire.error { throw IpcError(message: error) }
        guard let name = wire.result?.name, !name.isEmpty else {
            throw IpcError(message: "hzd 应答缺少注册身份")
        }
        return name
    }

    public func down() async throws {
        let line = try await requestOne(method: "down", params: [:])
        if let error = Self.errorMessage(line) {
            throw IpcError(message: error)
        }
    }

    public func loginPoll() async throws -> LoginProgress {
        let line = try await requestOne(method: "login_poll", params: [:])
        struct Wire: Decodable {
            var result: LoginEnvelope?
            var error: String?
        }
        struct LoginEnvelope: Decodable {
            var state: String
            var error: String?
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: line) else {
            throw IpcError(message: "无法解析 hzd 应答")
        }
        if let error = wire.error { throw IpcError(message: error) }
        guard let envelope = wire.result else {
            throw IpcError(message: "hzd 应答缺少登录进度")
        }
        switch envelope.state {
        case "idle": return .idle
        case "pending": return .pending
        case "completed": return .completed
        case "failed": return .failed(envelope.error ?? "登录失败")
        default: return .failed("未知登录进度：\(envelope.state)")
        }
    }

    public func diagnostics() async throws -> DiagnosticsReport {
        let line = try await requestOne(method: "diagnostics", params: [:])
        struct Wire: Decodable {
            var result: DiagnosticsReport?
            var error: String?
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: line) else {
            throw IpcError(message: "无法解析 hzd 应答")
        }
        if let error = wire.error { throw IpcError(message: error) }
        guard let report = wire.result else {
            throw IpcError(message: "hzd 应答缺少诊断内容")
        }
        return report
    }

    static func errorMessage(_ line: Data) -> String? {
        struct Wire: Decodable { var error: String? }
        return (try? JSONDecoder().decode(Wire.self, from: line))?.error
    }

    private func requestOne(method: String, params: [String: String]) async throws -> Data {
        let paramsJSON = String(
            decoding: (try? JSONEncoder().encode(params)) ?? Data("{}".utf8),
            as: UTF8.self
        )
        let request = "{\"id\":1,\"method\":\"\(method)\",\"params\":\(paramsJSON)}"
        let session = try await Session(socketPath: socketPath)
        return try await session.request(request)
    }

    // MARK: - 连接会话

    /// 一条 UDS 连接：写一行请求，读一行（request）或逐行直到 EOF/超时
    /// （exchange）。45 秒无行视为断开。
    final class Session {
        let connection: NWConnection
        nonisolated(unsafe) var continuation:
            CheckedContinuation<Data, Error>?

        init(socketPath: String) async throws {
            let endpoint = NWEndpoint.unix(path: socketPath)
            connection = NWConnection(to: endpoint, using: .tcp)
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                // NWConnection 状态回调可能多次触发：只 resume 一次。
                let once = Once()
                let report: @Sendable (Error?) -> Void = { error in
                    guard once.claim() else { return }
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: report(nil)
                    case .failed(let error): report(error)
                    case .cancelled: report(IpcError(message: "连接已取消"))
                    default: break
                    }
                }
                connection.start(queue: .global())
            }
        }

        deinit {
            connection.cancel()
        }

        /// 一问一答：写请求行，读首行响应。
        func request(_ text: String) async throws -> Data {
            try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                connection.send(content: Data((text + "\n").utf8), completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    }
                })
                receiveLine { line in
                    guard let line else {
                        continuation.resume(
                            throwing: IpcError(message: "hzd 关闭连接而没有响应"))
                        return
                    }
                    continuation.resume(returning: line)
                }
            }
        }

        /// 订阅：写请求行，逐行回调直到断开 / 45 秒无行 / 抛错。
        func exchange(
            request: String,
            onLine: @escaping (Data) -> Void
        ) async throws {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                var receivedAny = false
                var closed = false
                let finish: (Error?) -> Void = { error in
                    guard !closed else { return }
                    closed = true
                    self.connection.cancel()
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
                var timeoutTask: Task<Void, Never>?
                let armTimeout = {
                    timeoutTask?.cancel()
                    timeoutTask = Task {
                        try? await Task.sleep(for: .seconds(45))
                        guard !Task.isCancelled else { return }
                        finish(IpcError(message: "45 秒未收到任何推送，订阅断开"))
                    }
                }
                connection.send(
                    content: Data((request + "\n").utf8),
                    completion: .contentProcessed { error in
                        if let error {
                            finish(error)
                            return
                        }
                        armTimeout()
                        self.receiveStreaming(onLine: { line in
                            receivedAny = true
                            armTimeout()
                            onLine(line)
                        }, onEnd: { error in
                            // 服务端正常收尾也算会话完成。
                            finish(receivedAny ? nil : (error ?? IpcError(message: "订阅连接被关闭")))
                        })
                    }
                )
            }
        }

        private func receiveLine(_ completion: @escaping (Data?) -> Void) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, isComplete, error in
                if let data, !data.isEmpty {
                    self.buffer.append(data)
                    if let line = self.takeLine() {
                        completion(line)
                        return
                    }
                    self.receiveLine(completion)
                    return
                }
                if isComplete || error != nil {
                    completion(self.takeLine() ?? (self.buffer.isEmpty ? nil : self.buffer))
                    return
                }
                self.receiveLine(completion)
            }
        }

        private func receiveStreaming(
            onLine: @escaping (Data) -> Void,
            onEnd: @escaping (Error?) -> Void
        ) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, isComplete, error in
                if let data, !data.isEmpty {
                    self.buffer.append(data)
                    while let line = self.takeLine() {
                        onLine(line)
                    }
                }
                if let error {
                    onEnd(error)
                    return
                }
                if isComplete {
                    onEnd(nil)
                    return
                }
                self.receiveStreaming(onLine: onLine, onEnd: onEnd)
            }
        }

        private var buffer = Data()

        private func takeLine() -> Data? {
            guard let index = buffer.firstIndex(of: UInt8(ascii: "\n")) else { return nil }
            let line = buffer[buffer.startIndex..<index]
            buffer.removeSubrange(buffer.startIndex...index)
            return Data(line)
        }
    }
}

/// 一次性触发闸（回调只生效第一次）。
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    /// 返回是否首次（调用方据此决定是否执行）。
    func claim() -> Bool {
        lock.withLock {
            if claimed { return false }
            claimed = true
            return true
        }
    }
}
