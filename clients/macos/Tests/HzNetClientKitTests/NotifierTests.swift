import Foundation

@testable import HzNetClientKit

/// #89：通知触发时点、不重复发送、对端变化不通知、版本提示触发。
struct NotifierTests {
    func now(_ secondsSinceEpoch: TimeInterval) -> Date {
        Date(timeIntervalSince1970: secondsSinceEpoch)
    }

    /// 冲突修复时间戳：60 秒前（时效内）；`now(_:)` 的基准与它同源。
    let reference = Date()
    var repairAt: Int64 { Int64(reference.timeIntervalSince1970) - 60 }

    func snapshot(
        expiresAtUnix: Int64? = nil,
        vpnConflict: Bool = false,
        versionHint: String = "",
        peers: [Peer] = []
    ) -> StatusSnapshot {
        StatusSnapshot(
            registered: true,
            expiresAtUnix: expiresAtUnix,
            desiredState: "up",
            versionHint: versionHint,
            peers: peers,
            diagnostics: vpnConflict
                ? DiagnosticsInfo(
                    routeRepair: .init(at: repairAt, cidr: "c", previous: "taken_by:utun9"),
                    dnsFallback: nil
                )
                : nil
        )
    }

    /// 3 天 / 1 天触发时点：恰好 3 天外不发；进入 3 天发一次；进入 1 天再发。
    func testExpiryThresholds() {
        var engine = NotificationEngine()
        // base = reference（now(0)）；expiry 是相对 reference 的绝对秒。
        let base: TimeInterval = reference.timeIntervalSince1970
        let expiry = Int64(base + 4 * 86_400)

        // 4 天：不发。
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: expiry), now: now(base)) == [])
        // 进入 3 天窗口（恰 3 天）：一条 3 天通知。
        let at3Days = base + 86_400
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: expiry), now: now(at3Days)) == [.expiresIn3Days])
        // 同一窗口内重复评估：不重发。
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: expiry), now: now(at3Days + 60)) == [])
        // 进入 1 天窗口：一条 1 天通知（3 天不再发）。
        let at1Day = base + 3 * 86_400
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: expiry), now: now(at1Day)) == [.expiresIn1Day])
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: expiry), now: now(at1Day + 60)) == [])
    }

    /// 同一到期点不重复；续期后新到期点可再发（条件消失再成立可再发）。
    func testRenewalResetsExpiryNotifications() {
        var engine = NotificationEngine()
        let base: TimeInterval = reference.timeIntervalSince1970
        let oldExpiry = Int64(base + 2 * 86_400)
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: oldExpiry), now: now(base)) == [.expiresIn3Days])
        // 续期到 10 天后：条件消失。
        let renewed = Int64(base + 10 * 86_400)
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: renewed), now: now(base)) == [])
        // 再次滑进 3 天窗口：重新发。
        hzExpect(engine.evaluate(
                snapshot: snapshot(expiresAtUnix: renewed), now: now(base + 8 * 86_400)) == [.expiresIn3Days])
        // 旧到期点即使瞬时又出现（时钟回拨场景）也不重发。
        hzExpect(engine.evaluate(snapshot: snapshot(expiresAtUnix: oldExpiry), now: now(base)) == [])
    }

    /// VPN 冲突：从无到有发一次；消失后再次出现可再发。
    func testVpnConflictEdges() {
        var engine = NotificationEngine()
        hzExpect(engine.evaluate(snapshot: snapshot(vpnConflict: false), now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: snapshot(vpnConflict: true), now: now(0)) == [.vpnConflict])
        hzExpect(engine.evaluate(snapshot: snapshot(vpnConflict: true), now: now(0)) == [])
        // 冲突消失 → 再出现：再发。
        hzExpect(engine.evaluate(snapshot: snapshot(vpnConflict: false), now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: snapshot(vpnConflict: true), now: now(0)) == [.vpnConflict])
    }

    /// 版本提示：空 → behind 发一次；清空 → 再出现再发。
    func testVersionHintEdges() {
        var engine = NotificationEngine()
        hzExpect(engine.evaluate(snapshot: snapshot(versionHint: ""), now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: snapshot(versionHint: "behind"), now: now(0)) == [.versionOutdated("behind")])
        hzExpect(engine.evaluate(snapshot: snapshot(versionHint: "behind"), now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: snapshot(versionHint: "at_min"), now: now(0)) == [])
        // 升级后提示消失，再次落后（新 coord 又升级）：再发。
        hzExpect(engine.evaluate(snapshot: snapshot(versionHint: ""), now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: snapshot(versionHint: "at_min"), now: now(0)) == [.versionOutdated("at_min")])
    }

    /// 对端上下线 / 路径变化：永不通知。
    func testPeerChangesNeverNotify() {
        var engine = NotificationEngine()
        let offline = snapshot(peers: [])
        let online = snapshot(peers: [
            Peer(name: "a", ipv4: "1", ipv6: "2", path: "direct", endpoint: "x"),
        ])
        hzExpect(engine.evaluate(snapshot: offline, now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: online, now: now(0)) == [])
        hzExpect(engine.evaluate(snapshot: offline, now: now(0)) == [])
    }

    /// 组合：同一次评估至多发 3/1 天各一条 + 冲突 + 版本各一条（极端快照）。
    func testMultipleKindsInOneSnapshot() {
        var engine = NotificationEngine()
        let base: TimeInterval = reference.timeIntervalSince1970
        let snapshot = StatusSnapshot(
            registered: true,
            expiresAtUnix: Int64(base + 12 * 3_600),  // 12 小时 → 同时在 3 天与 1 天窗口
            desiredState: "up",
            versionHint: "behind",
            peers: [],
            diagnostics: DiagnosticsInfo(
                routeRepair: .init(at: repairAt, cidr: "c", previous: "taken_by:utun9"),
                dnsFallback: nil
            )
        )
        hzExpect(engine.evaluate(snapshot: snapshot, now: now(base)) == [.expiresIn3Days, .expiresIn1Day, .vpnConflict, .versionOutdated("behind")])
    }
}
