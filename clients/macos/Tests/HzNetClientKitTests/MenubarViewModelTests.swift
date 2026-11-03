import Foundation

@testable import HzNetClientKit

/// #85/#86：菜单栏视图模型经假后端事件流的派生行为（状态 / 对端行 /
/// 引导窗弹出条件 / 通知联动）。
@MainActor
struct MenubarViewModelTests {
    func connected(_ snapshot: StatusSnapshot?) -> (ConnectionState, StatusSnapshot?) {
        (.connected, snapshot)
    }

    func testStatusFollowsEventStream() async {
        let backend = FakeBackend()
        let model = MenubarViewModel(backend: backend)
        model.start()

        backend.emit((.reconnecting(afterSeconds: 1), nil))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(model.status == .hzdNotRunning)

        backend.emit(connected(StatusSnapshot(registered: false, desiredState: "up")))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(model.status == .disconnected, "未注册：引导窗负责接入")

        backend.emit(connected(StatusSnapshot(registered: true, name: "mini", desiredState: "up")))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(model.status == .connected)
        hzExpect(model.snapshot?.name == "mini")
    }

    func testOnboardingShowsOnlyWhenConnectedAndUnregistered() async {
        let backend = FakeBackend()
        let model = MenubarViewModel(backend: backend)
        model.start()

        backend.emit((.reconnecting(afterSeconds: 1), nil))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(!(model.showsOnboarding), "hzd 不可达时不弹（还不知道是否注册）")

        backend.emit(connected(StatusSnapshot(registered: false, desiredState: "up")))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(model.showsOnboarding)

        backend.emit(connected(StatusSnapshot(registered: true, name: "mini", desiredState: "up")))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(!(model.showsOnboarding))
    }

    func testToggleCallsUpWhenDownAndDownWhenUp() async {
        let backend = FakeBackend()
        let model = MenubarViewModel(backend: backend)
        model.start()

        backend.emit(connected(StatusSnapshot(registered: true, name: "mini", desiredState: "down")))
        try? await Task.sleep(for: .milliseconds(300))
        await model.toggleConnection()
        hzExpect(backend.calls == ["up"], "down → up")

        backend.emit(connected(StatusSnapshot(registered: true, name: "mini", desiredState: "up")))
        try? await Task.sleep(for: .milliseconds(300))
        await model.toggleConnection()
        hzExpect(backend.calls == ["up", "down"], "up → down")
    }

    func testNotificationsFlowThroughEvaluate() async {
        let backend = FakeBackend()
        let model = MenubarViewModel(backend: backend)
        var received: [AppNotification] = []
        model.notify = { received.append($0) }
        model.start()

        // 到期 12 小时 + 版本过旧：一次评估应发 3 天 / 1 天 / 版本三条。
        let base = Date()
        let snapshot = StatusSnapshot(
            registered: true,
            expiresAtUnix: Int64(base.timeIntervalSince1970 + 12 * 3_600),
            desiredState: "up",
            versionHint: "behind"
        )
        backend.emit(connected(snapshot))
        try? await Task.sleep(for: .milliseconds(300))

        hzExpect(Set(received.map(\.identifier)) == Set([AppNotification.expiresIn3Days, .expiresIn1Day, .versionOutdated("behind")].map(\.identifier)))
        // 下一条相同快照（心跳）：不重发。
        received.removeAll()
        backend.emit(connected(snapshot))
        try? await Task.sleep(for: .milliseconds(300))
        hzExpect(received.isEmpty)
    }

    func testReloginOpensBrowser() async {
        let backend = FakeBackend()
        backend.upOutcome = .loginStarted(url: "https://coord.example.com/oidc/start/n-x")
        let model = MenubarViewModel(backend: backend)
        var opened: [String] = []
        model.openURL = { opened.append($0) }

        await model.relogin()
        hzExpect(opened == ["https://coord.example.com/oidc/start/n-x"])
        hzExpect(backend.calls == ["up"])
    }
}
