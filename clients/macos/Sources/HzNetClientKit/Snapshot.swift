import Foundation

/// IPC status / subscribe 快照（#85 契约）。字段与 hzd `status_value` 的
/// JSON 一一对应（snake_case），由 `clients/fixtures/` 的 Rust 生成文件
/// 锁定；可选性覆盖各 fixture 的字段差异（未注册快照没有身份字段）。
public struct StatusSnapshot: Codable, Equatable, Sendable {
    public var registered: Bool
    /// 仅过期态出现（hzd NodeStatus 的稳定契约）。
    public var expired: Bool?
    // ---- 身份（已注册 / 已过期才有）----
    public var name: String?
    public var ipv4: String?
    public var ipv6: String?
    public var expiresAtUnix: Int64?
    public var dnsSuffix: String?
    /// 注册时连接的 Coordination Server（#88 深链校验）；未注册为空。
    public var coordAddr: String?

    public var desiredState: String
    public var revoked: Bool?
    /// coord 版本提示（#89）：`behind` / `at_min`；旧 coord 为空。
    public var versionHint: String?
    public var peers: [Peer]?
    public var diagnostics: DiagnosticsInfo?
    public var policy: PolicyInfo?

    public enum CodingKeys: String, CodingKey {
        case registered
        case expired
        case name
        case ipv4
        case ipv6
        case expiresAtUnix = "expires_at_unix"
        case dnsSuffix = "dns_suffix"
        case coordAddr = "coord_addr"
        case desiredState = "desired_state"
        case revoked
        case versionHint = "version_hint"
        case peers
        case diagnostics
        case policy
    }

    public init(
        registered: Bool,
        expired: Bool? = nil,
        name: String? = nil,
        ipv4: String? = nil,
        ipv6: String? = nil,
        expiresAtUnix: Int64? = nil,
        dnsSuffix: String? = nil,
        coordAddr: String? = nil,
        desiredState: String,
        revoked: Bool? = nil,
        versionHint: String? = nil,
        peers: [Peer]? = nil,
        diagnostics: DiagnosticsInfo? = nil,
        policy: PolicyInfo? = nil
    ) {
        self.registered = registered
        self.expired = expired
        self.name = name
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.expiresAtUnix = expiresAtUnix
        self.dnsSuffix = dnsSuffix
        self.coordAddr = coordAddr
        self.desiredState = desiredState
        self.revoked = revoked
        self.versionHint = versionHint
        self.peers = peers
        self.diagnostics = diagnostics
        self.policy = policy
    }

    /// 到期时刻（Date）；无到期信息为 nil。
    public var expiresAt: Date? {
        expiresAtUnix.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// 点击对端复制的网内域名（#86）。
    public func peerDomain(_ peer: Peer) -> String? {
        guard let suffix = dnsSuffix else { return nil }
        return "\(peer.name).\(suffix)"
    }
}

/// 一个对端（hzd MapPeer + 中转原因）。
public struct Peer: Codable, Equatable, Sendable, Identifiable {
    public var name: String
    public var ipv4: String
    public var ipv6: String
    public var endpoints: [String]?
    public var handshakeSecs: Int?
    /// `direct` / `relay`；数据面未拉起为 nil。
    public var path: String?
    /// 直连时在用的 Endpoint。
    public var endpoint: String?
    /// 走 Relay 的本地判定原因（规格 §4）；直连为 nil。
    public var relayReason: String?

    public var id: String { name }

    public enum CodingKeys: String, CodingKey {
        case name
        case ipv4
        case ipv6
        case endpoints
        case handshakeSecs = "handshake_secs"
        case path
        case endpoint
        case relayReason = "relay_reason"
    }

    public init(
        name: String,
        ipv4: String,
        ipv6: String,
        endpoints: [String]? = nil,
        handshakeSecs: Int? = nil,
        path: String? = nil,
        endpoint: String? = nil,
        relayReason: String? = nil
    ) {
        self.name = name
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.endpoints = endpoints
        self.handshakeSecs = handshakeSecs
        self.path = path
        self.endpoint = endpoint
        self.relayReason = relayReason
    }

    public var isDirect: Bool { path == "direct" }

    /// 中转原因的中文说明（#86 菜单 / #84 runbook 同一套词汇）。
    public var relayReasonText: String? {
        switch relayReason {
        case "local_udp_broken": return "本机 UDP 外发失败"
        case "no_candidates": return "对端无可用候选"
        case "handshake_timeout": return "握手超时（对端安全组未放行？）"
        case "punch_pending": return "打洞进行中"
        default: return relayReason
        }
    }
}

/// status.diagnostics：运行时修复记录（#25 / #86 VPN 冲突信号）。
public struct DiagnosticsInfo: Codable, Equatable, Sendable {
    public struct RouteRepair: Codable, Equatable, Sendable {
        public var at: Int64
        public var cidr: String
        /// `ours` / `missing` / `taken_by:<iface>`。
        public var previous: String
    }

    public var routeRepair: RouteRepair?
    public var dnsFallback: String?

    public enum CodingKeys: String, CodingKey {
        case routeRepair = "route_repair"
        case dnsFallback = "dns_fallback"
    }

    /// VPN 冲突信号（#86）：最近 15 分钟内路由曾被其他网卡占用（taken_by）
    /// ——第三方 TUN 类工具在场的运行时证据（复用 #25 的检测；持续冲突下
    /// route_guard 的反复修复会刷新时间戳，一次性冲突 15 分钟后恢复）。
    public var vpnConflict: Bool {
        guard let repair = routeRepair,
              repair.previous.hasPrefix("taken_by")
        else { return false }
        let at = Date(timeIntervalSince1970: TimeInterval(repair.at))
        return Date().timeIntervalSince(at) <= 15 * 60
    }

    /// 可测版本：`now` 注入（时效判定）。
    public func vpnConflict(asOf now: Date) -> Bool {
        guard let repair = routeRepair,
              repair.previous.hasPrefix("taken_by")
        else { return false }
        let at = Date(timeIntervalSince1970: TimeInterval(repair.at))
        return now.timeIntervalSince(at) <= 15 * 60
    }
}

public struct PolicyInfo: Codable, Equatable, Sendable {
    public var version: Int
    public var dropped: Int
}

/// IPC login_poll 的进度（serde tag=state）。
public enum LoginProgress: Equatable, Sendable {
    case idle
    case pending
    case completed
    case failed(String)

    public static func decode(_ data: Data) -> LoginProgress? {
        struct Wire: Decodable {
            var state: String
            var error: String?
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: data) else { return nil }
        switch wire.state {
        case "idle": return .idle
        case "pending": return .pending
        case "completed": return .completed
        case "failed": return .failed(wire.error ?? "未知错误")
        default: return nil
        }
    }
}

/// diagnostics IPC 响应（#84）。
public struct DiagnosticsReport: Codable, Equatable, Sendable {
    public var status: StatusSnapshot
    public var version: String
    public var os: String
    public var arch: String
    /// netcheck 的原始对象（六项结论；App 只透传给诊断包，不建强类型）。
    public var netcheck: JSONValue
    public var logTail: [String]
    public var logNote: String?
    /// 载荷 schema 版本（#109）。缺省表示旧 hzd，无此字段。
    public var schemaVersion: Int?
    /// 采集时刻，UTC RFC3339。缺省表示旧 hzd。
    public var collectedAt: String?

    public enum CodingKeys: String, CodingKey {
        case status
        case version
        case os
        case arch
        case netcheck
        case logTail = "log_tail"
        case logNote = "log_note"
        case schemaVersion = "schema_version"
        case collectedAt = "collected_at"
    }
}

/// 保留原形的 JSON 值（netcheck 透传用）。
public enum JSONValue: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: JSONValue].self))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// pretty JSON 文本（诊断包导出用）。
    public var prettyText: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(self) else { return "null" }
        return String(decoding: data, as: UTF8.self)
    }
}
