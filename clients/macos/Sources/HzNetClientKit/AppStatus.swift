import Foundation

/// 菜单栏图标状态（#86 / 规格 §5 表）：自上而下取第一条命中。
/// 判定是纯函数，经假后端喂快照做表驱动测试。
public enum AppStatus: Equatable, Sendable {
    case hzdNotRunning
    case needsRelogin
    case vpnConflict
    case disconnected
    case partialRelay
    case connected

    /// 判定链（顺序即优先级，规格 §5）：
    /// hzd 未运行 → 需要重新登录（expired / revoked）→ 与其他 VPN 冲突
    /// （路由被第三方网卡占用的修复记录，复用 #25）→ 已断开
    /// （desired_state=down）→ 部分中转（存在原因不是 punch_pending 的
    /// Relayed 对端）→ 已连接。
    ///
    /// 未注册（从未加入）不在六态表里：引导窗负责接入；菜单态归
    /// disconnected——数据面确实没起，且不与更高优先级冲突。
    public static func determine(
        connection: ConnectionState,
        snapshot: StatusSnapshot?,
        asOf now: Date = Date()
    ) -> AppStatus {
        guard connection.isConnected, let snapshot else {
            return .hzdNotRunning
        }
        if snapshot.expired == true || snapshot.revoked == true {
            return .needsRelogin
        }
        if !snapshot.registered {
            // 从未加入：六态表未列，归已断开——引导窗负责接入（MC-7），
            // 菜单图标不给"已连接"的错误信号。
            return .disconnected
        }
        if snapshot.diagnostics?.vpnConflict(asOf: now) == true {
            return .vpnConflict
        }
        if snapshot.desiredState == "down" {
            return .disconnected
        }
        let relayedNeedsAttention = (snapshot.peers ?? []).contains { peer in
            peer.path == "relay"
                && peer.relayReason != nil
                && peer.relayReason != "punch_pending"
        }
        if relayedNeedsAttention {
            return .partialRelay
        }
        return .connected
    }

    /// 菜单栏标题（SF Symbol 名）。
    public var symbolName: String {
        switch self {
        case .hzdNotRunning: return "exclamationmark.circle"
        case .needsRelogin: return "arrow.clockwise.circle"
        case .vpnConflict: return "exclamationmark.shield"
        case .disconnected: return "pause.circle"
        case .partialRelay: return "arrow.triangle.branch"
        case .connected: return "checkmark.circle"
        }
    }

    /// 状态行的中文说明（悬停 / 菜单顶部）。
    public var title: String {
        switch self {
        case .hzdNotRunning: return "hzd 未运行"
        case .needsRelogin: return "需要重新登录"
        case .vpnConflict: return "与其他 VPN 工具冲突"
        case .disconnected: return "已断开"
        case .partialRelay: return "部分对端走中转"
        case .connected: return "已连接"
        }
    }
}

/// 对端列表行（#86 菜单展示数据）：路径、原因中文说明、延迟。
public struct PeerRow: Equatable, Sendable, Identifiable {
    public let name: String
    public let ipv4: String
    public let ipv6: String
    /// `Direct Path` / `Relayed Path（原因…）` / `未知`。
    public let pathText: String
    /// 点击复制的网内域名（`<name>.hznet.internal`）。
    public let domain: String?
    /// 最近握手距今秒数（延迟参考）；从未握手为 nil。
    public let handshakeSecs: Int?

    public var id: String { name }

    /// 从快照构造菜单行（纯函数，可测）。
    public static func rows(snapshot: StatusSnapshot?) -> [PeerRow] {
        guard let snapshot else { return [] }
        return (snapshot.peers ?? []).map { peer in
            let pathText: String
            if peer.isDirect {
                pathText = "Direct Path"
            } else if peer.path == "relay" {
                if let reason = peer.relayReasonText {
                    pathText = "Relayed Path（\(reason)）"
                } else {
                    pathText = "Relayed Path"
                }
            } else {
                pathText = "未知"
            }
            return PeerRow(
                name: peer.name,
                ipv4: peer.ipv4,
                ipv6: peer.ipv6,
                pathText: pathText,
                domain: snapshot.peerDomain(peer),
                handshakeSecs: peer.handshakeSecs
            )
        }
    }
}
