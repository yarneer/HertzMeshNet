import Foundation

@testable import HzNetClientKit

/// #86：六种状态的判定链表驱动（含优先级），经快照直接喂（与假后端
/// 事件流串联的集成行为在 MenubarViewModelTests 覆盖）。
struct AppStatusTests {
    func connected(_ snapshot: StatusSnapshot) -> (ConnectionState, StatusSnapshot?) {
        (.connected, snapshot)
    }

    /// 判定基准时刻：冲突修复发生在 60 秒前（15 分钟时效内）。
    let now = Date()
    var repairAt: Int64 { Int64(now.timeIntervalSince1970) - 60 }

    func snapshot(
        registered: Bool = true,
        expired: Bool? = nil,
        revoked: Bool? = false,
        routeRepairPrevious: String? = nil,
        desiredState: String = "up",
        peers: [Peer] = []
    ) -> StatusSnapshot {
        var diagnostics: DiagnosticsInfo?
        if let routeRepairPrevious {
            diagnostics = DiagnosticsInfo(
                routeRepair: .init(at: repairAt, cidr: "100.96.0.0/16", previous: routeRepairPrevious),
                dnsFallback: nil
            )
        }
        return StatusSnapshot(
            registered: registered,
            expired: expired,
            name: registered ? "mini" : nil,
            desiredState: desiredState,
            revoked: revoked,
            peers: peers,
            diagnostics: diagnostics
        )
    }

    /// 规格表逐行：自上而下取第一条命中。
    func testPriorityChain() {
        let cases: [(String, ConnectionState, StatusSnapshot?, AppStatus)] = [
            // hzd 未运行优先于一切。
            ("hzd 未运行", .reconnecting(afterSeconds: 5), nil, .hzdNotRunning),
            (
                "未运行优先于过期", .reconnecting(afterSeconds: 1),
                snapshot(expired: true), .hzdNotRunning
            ),
            // 需要重新登录：expired / revoked。
            ("过期", .connected, snapshot(expired: true), .needsRelogin),
            ("吊销", .connected, snapshot(revoked: true), .needsRelogin),
            (
                "过期优先于 down 与冲突", .connected,
                snapshot(expired: true, routeRepairPrevious: "taken_by:utun9", desiredState: "down"),
                .needsRelogin
            ),
            // VPN 冲突（路由被第三方网卡占用）。
            ("冲突", .connected, snapshot(routeRepairPrevious: "taken_by:utun9"), .vpnConflict),
            (
                "冲突优先于 down", .connected,
                snapshot(routeRepairPrevious: "taken_by:utun9", desiredState: "down"), .vpnConflict
            ),
            // 我们自己恢复的普通删除不算冲突。
            ("路由被删不算冲突", .connected, snapshot(routeRepairPrevious: "missing"), .connected),
            // 15 分钟外的修复记录不再算冲突（一次性冲突不永久滞留）。
            ("过期的修复记录不算冲突", .connected,
             StatusSnapshot(
                registered: true, name: "mini", desiredState: "up",
                peers: [],
                diagnostics: DiagnosticsInfo(
                    routeRepair: .init(
                        at: Int64(now.timeIntervalSince1970) - 16 * 60,
                        cidr: "100.96.0.0/16",
                        previous: "taken_by:utun9"
                    ),
                    dnsFallback: nil
                )
             ),
             .connected),
            // 已断开。
            ("down", .connected, snapshot(desiredState: "down"), .disconnected),
            // 部分中转：原因不是 punch_pending 的 Relayed 对端。
            (
                "中转（握手超时）", .connected,
                snapshot(peers: [
                    Peer(name: "a", ipv4: "1", ipv6: "2", path: "relay", relayReason: "handshake_timeout"),
                ]),
                .partialRelay
            ),
            (
                "punch_pending 不算部分中转", .connected,
                snapshot(peers: [
                    Peer(name: "a", ipv4: "1", ipv6: "2", path: "relay", relayReason: "punch_pending"),
                ]),
                .connected
            ),
            (
                "中转优先于纯直连混布", .connected,
                snapshot(peers: [
                    Peer(name: "a", ipv4: "1", ipv6: "2", path: "direct", endpoint: "x"),
                    Peer(name: "b", ipv4: "1", ipv6: "2", path: "relay", relayReason: "no_candidates"),
                ]),
                .partialRelay
            ),
            // 已连接。
            ("全直连", .connected, snapshot(peers: [
                Peer(name: "a", ipv4: "1", ipv6: "2", path: "direct", endpoint: "x"),
            ]), .connected),
            // 未注册归 disconnected（引导窗负责接入）。
            ("未注册", .connected, snapshot(registered: false, revoked: nil), .disconnected),
        ]
        for (label, connection, snapshot, expected) in cases {
            hzExpect(AppStatus.determine(connection: connection, snapshot: snapshot, asOf: now) == expected, "\(label)")
        }
    }

    /// #86：对端行的中文文案与复制域名。
    func testPeerRows() {
        let snapshot = StatusSnapshot(
            registered: true,
            name: "mini",
            dnsSuffix: "hznet.internal",
            desiredState: "up",
            peers: [
                Peer(name: "beefy-pc", ipv4: "100.96.0.2", ipv6: "::2", handshakeSecs: 5,
                     path: "direct", endpoint: "203.0.113.9:41001"),
                Peer(name: "cloud-vm", ipv4: "100.96.0.3", ipv6: "::3", handshakeSecs: 12,
                     path: "relay", relayReason: "handshake_timeout"),
                Peer(name: "fresh", ipv4: "100.96.0.4", ipv6: "::4", path: "relay",
                     relayReason: "punch_pending"),
            ]
        )
        let rows = PeerRow.rows(snapshot: snapshot)
        hzExpect(rows.count == 3)
        hzExpect(rows[0].pathText == "Direct Path")
        hzExpect(rows[0].domain == "beefy-pc.hznet.internal")
        hzExpect(rows[0].handshakeSecs == 5)
        hzExpect(rows[1].pathText == "Relayed Path（握手超时（对端安全组未放行？））")
        hzExpect(rows[1].domain == "cloud-vm.hznet.internal")
        hzExpect(rows[2].pathText == "Relayed Path（打洞进行中）")
    }
}
