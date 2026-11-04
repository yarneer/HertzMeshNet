import Foundation

@testable import HzNetClientKit

// CLT（无 Xcode）跑不了 XCTest / Swift Testing 宏——测试自带极简断言。
// 每个 Suite 是一个 struct，main 按序调用全部测试方法，失败计数决定退出码。

enum HzTest {
    nonisolated(unsafe) static var failures = 0
    nonisolated(unsafe) static var current = ""

    static func fail(_ comment: String, file: StaticString = #fileID, line: UInt = #line) {
        failures += 1
        print("✗ [\(current)] \(file):\(line) \(comment)")
    }
}

func hzExpect(
    _ condition: Bool,
    _ comment: @autoclosure () -> String = "",
    file: StaticString = #fileID,
    line: UInt = #line
) {
    if !condition {
        HzTest.fail(comment(), file: file, line: line)
    }
}

func hzExpectEqual<T: Equatable>(
    _ actual: T,
    _ expected: T,
    _ comment: @autoclosure () -> String = "",
    file: StaticString = #fileID,
    line: UInt = #line
) {
    if actual != expected {
        HzTest.fail("\(comment()) 实际 \(actual) ≠ 期望 \(expected)", file: file, line: line)
    }
}

func hzRequire<T>(_ value: T?, _ comment: String = "", file: StaticString = #fileID, line: UInt = #line) throws -> T {
    guard let value else {
        HzTest.fail(comment.isEmpty ? "require 失败" : comment, file: file, line: line)
        throw TestAbort()
    }
    return value
}

func hzFail(_ message: String, file: StaticString = #fileID, line: UInt = #line) {
    HzTest.fail(message, file: file, line: line)
}

struct TestAbort: Error {}

func runSuite(_ name: String, _ body: () throws -> Void) {
    HzTest.current = name
    let started = HzTest.failures
    do {
        try body()
    } catch {
        // 测试体内的 hzRequire 失败以 TestAbort 中断该测试，失败已计数。
    }
    let suiteFailures = HzTest.failures - started
    print(suiteFailures == 0 ? "✓ \(name)" : "✗ \(name)（\(suiteFailures) 项失败）")
}

@MainActor
func runAsyncSuite(_ name: String, _ body: () async throws -> Void) async {
    HzTest.current = name
    let started = HzTest.failures
    do {
        try await body()
    } catch {
    }
    let suiteFailures = HzTest.failures - started
    print(suiteFailures == 0 ? "✓ \(name)" : "✗ \(name)（\(suiteFailures) 项失败）")
}

// hzExpectEqual(a, b, "msg") 宏替换后的形态是 hzExpect(a == b, "msg")，
// 直接可用；hzRequire 需要 throws。main 汇总：

@main
struct TestMain {
    @MainActor
    static func main() async {
        let started = HzTest.failures

        runSuite("AppStatusTests") {
            let suite = AppStatusTests()
            suite.testPriorityChain()
            suite.testPeerRows()
        }
        runSuite("SnapshotDecodingTests") {
            let suite = SnapshotDecodingTests()
            try suite.testUnregisteredSnapshot()
            try suite.testRegisteredDirectSnapshot()
            try suite.testRegisteredRelaySnapshotCarriesReason()
            try suite.testConflictSnapshotExposesVpnConflict()
            try suite.testExpiredAndDownSnapshots()
            try suite.testLoginProgressWire()
            try suite.testDiagnosticsReport()
        }
        runSuite("DeepLinkTests") {
            let suite = DeepLinkTests()
            suite.testValidLink()
            suite.testNonHttpsCoordRejected()
            suite.testRegisteredToDifferentCoordRejected()
            suite.testRegisteredToSameCoordIsInformational()
            suite.testMissingOrMalformedParameters()
        }
        runSuite("DiagnosticsExportTests") {
            let suite = DiagnosticsExportTests()
            suite.testDefaultFileName()
            try suite.testArchiveContainsSingleJsonEntry()
            try suite.testUnzipVerifiesArchive()
            try suite.testWriteArchiveTightensToOwnerOnly()
            suite.testCrc32KnownVector()
            suite.testEmptyArchiveThrows()
        }
        runSuite("NotifierTests") {
            let suite = NotifierTests()
            suite.testExpiryThresholds()
            suite.testRenewalResetsExpiryNotifications()
            suite.testVpnConflictEdges()
            suite.testVersionHintEdges()
            suite.testPeerChangesNeverNotify()
            suite.testMultipleKindsInOneSnapshot()
        }
        await runAsyncSuite("OnboardingTests") {
            let suite = OnboardingTests()
            suite.testCoordValidation()
            try await suite.testBrowserLoginCompletes()
            try await suite.testBrowserLoginFailsAndCanRetry()
            try await suite.testInviteFailureSurfacesCoordReason()
            await suite.testInviteSuccess()
            suite.testDefaultCoordPrefilled()
        }
        await runAsyncSuite("MenubarViewModelTests") {
            let suite = MenubarViewModelTests()
            await suite.testStatusFollowsEventStream()
            await suite.testOnboardingShowsOnlyWhenConnectedAndUnregistered()
            await suite.testToggleCallsUpWhenDownAndDownWhenUp()
            await suite.testNotificationsFlowThroughEvaluate()
            await suite.testReloginOpensBrowser()
        }

        let total = HzTest.failures - started
        print("")
        print(total == 0 ? "全部通过" : "共 \(total) 项失败")
        exit(total == 0 ? 0 : 1)
    }
}
