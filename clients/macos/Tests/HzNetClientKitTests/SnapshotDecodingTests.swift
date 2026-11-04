import Foundation

@testable import HzNetClientKit

/// #85：Swift 解码 Rust 生成的全部契约 fixture——Rust 字段漂移会让 CI 的
/// fixture diff 检查先红；这里保证 Swift 侧逐字段可用。
struct SnapshotDecodingTests {
    static let fixturesRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // Tests/HzNetClientKitTests
        .deletingLastPathComponent()      // Tests
        .deletingLastPathComponent()      // clients/macos
        .deletingLastPathComponent()      // clients
        .appendingPathComponent("fixtures")

    func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: Self.fixturesRoot.appendingPathComponent(name))
    }

    func decodeSnapshot(_ name: String) throws -> StatusSnapshot {
        try JSONDecoder().decode(StatusSnapshot.self, from: fixture(name))
    }

    func testUnregisteredSnapshot() throws {
        let snapshot = try decodeSnapshot("status-unregistered.json")
        hzExpect(!(snapshot.registered))
        hzExpect(snapshot.expired == nil)
        hzExpect(snapshot.desiredState == "up")
    }

    func testRegisteredDirectSnapshot() throws {
        let snapshot = try decodeSnapshot("status-registered-direct.json")
        hzExpect(snapshot.registered)
        hzExpect(snapshot.name == "mini")
        hzExpect(snapshot.ipv4 == "100.96.0.1")
        hzExpect(snapshot.desiredState == "up")
        hzExpect(snapshot.versionHint == "")
        hzExpect(snapshot.coordAddr == "https://coord.example.com")
        let peers = try hzRequire(snapshot.peers)
        hzExpect(peers.count == 1)
        hzExpect(peers[0].name == "beefy-pc")
        hzExpect(peers[0].handshakeSecs == 4)
        hzExpect(peers[0].endpoint == "203.0.113.9:41001")
        hzExpect(snapshot.peerDomain(peers[0]) == "beefy-pc.hznet.internal")
    }

    func testRegisteredRelaySnapshotCarriesReason() throws {
        let snapshot = try decodeSnapshot("status-registered-relay.json")
        hzExpect(snapshot.versionHint == "behind")
        let relayed = try hzRequire(snapshot.peers?.first { $0.path == "relay" })
        hzExpect(relayed.relayReason == "handshake_timeout")
        hzExpect(relayed.relayReasonText == "握手超时（对端安全组未放行？）")
    }

    func testConflictSnapshotExposesVpnConflict() throws {
        let snapshot = try decodeSnapshot("status-registered-conflict.json")
        hzExpect(snapshot.diagnostics?.routeRepair?.previous == "taken_by:utun9")
        // 修复时间戳是 fixture 固定值（2026-04）：在该时刻后 60 秒内算冲突，
        // 15 分钟外不算（时效语义）。
        let repairMoment = Date(timeIntervalSince1970: 1_775_200_000)
        hzExpect(snapshot.diagnostics?.vpnConflict(asOf: repairMoment.addingTimeInterval(60)) == true)
        hzExpect(snapshot.diagnostics?.vpnConflict(asOf: repairMoment.addingTimeInterval(16 * 60)) == false)
    }

    func testExpiredAndDownSnapshots() throws {
        let expired = try decodeSnapshot("status-expired.json")
        hzExpect(!(expired.registered))
        hzExpect(expired.expired == true)
        hzExpect(expired.name == "mini", "过期仍携带身份")

        let down = try decodeSnapshot("status-down.json")
        hzExpect(down.registered)
        hzExpect(down.desiredState == "down")
        hzExpect(down.peers == [], "down 后没有对端")
    }

    func testLoginProgressWire() throws {
        hzExpect(LoginProgress.decode(try fixture("login-pending.json")) == .pending)
        hzExpect(LoginProgress.decode(try fixture("login-completed.json")) == .completed)
        guard case .failed(let reason) = LoginProgress.decode(try fixture("login-failed.json")) ?? .idle else {
            hzFail("login-failed 应解码为 failed")
        return
        }
        hzExpect(reason.contains("超时"), "\(reason)")
    }

    func testDiagnosticsReport() throws {
        let report = try JSONDecoder().decode(
            DiagnosticsReport.self, from: fixture("diagnostics.json"))
        hzExpect(report.version == "0.4.0 (a1b2c3d)")
        hzExpect(report.os == "macos")
        hzExpect(report.arch == "aarch64")
        hzExpect(report.status.name == "mini")
        hzExpect(report.logTail.count == 2)
        hzExpect(report.logNote != nil)
        hzExpect(report.schemaVersion == 1)
        hzExpect(report.collectedAt == "2026-10-29T10:00:01Z")
        hzExpect(report.netcheck.prettyText.contains("\"nat\""))
    }

    /// #109：旧载荷没有 schema_version / collected_at / log_note 时仍可解码。
    func testDiagnosticsReportDecodesLegacyPayload() throws {
        let legacy = Data(
            """
            {"arch":"x86_64","log_tail":[],"netcheck":null,"os":"linux","status":{"desired_state":"down","registered":false},"version":"0.3.0"}
            """.utf8)
        let report = try JSONDecoder().decode(DiagnosticsReport.self, from: legacy)
        hzExpect(report.schemaVersion == nil)
        hzExpect(report.collectedAt == nil)
        hzExpect(report.logNote == nil)
        hzExpect(report.version == "0.3.0")
        hzExpect(report.logTail.isEmpty)
    }
}
