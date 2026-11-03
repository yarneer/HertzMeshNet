import Foundation

@testable import HzNetClientKit

/// #87：引导窗三条路径（登录完成 / 登录过期失败 / 邀请码失败）的视图模型
/// 状态，经假后端驱动。
@MainActor
struct OnboardingTests {
    func testCoordValidation() {
        hzExpect(OnboardingViewModel.validCoord("https://coord.example.com"))
        hzExpect(OnboardingViewModel.validCoord("http://127.0.0.1:8080"))
        hzExpect(!(OnboardingViewModel.validCoord("coord.example.com")), "缺 scheme")
        hzExpect(!(OnboardingViewModel.validCoord("ftp://coord.example.com")))
        hzExpect(!(OnboardingViewModel.validCoord("https://")), "缺 host")
        hzExpect(!(OnboardingViewModel.validCoord("")))
        hzExpect(OnboardingViewModel.validCoord("  https://coord.example.com  "), "两端空白可容忍")
    }

    /// 浏览器登录完成：up 返回 login_url → 打开浏览器 → 轮询到 completed。
    func testBrowserLoginCompletes() async {
        let backend = FakeBackend()
        backend.upOutcome = .loginStarted(url: "https://coord.example.com/oidc/start/n-abc")
        backend.loginPollResult = .completed
        let model = OnboardingViewModel()
        var opened: [String] = []
        model.openURL = { opened.append($0) }

        await model.startBrowserLogin(backend: backend)

        hzExpect(model.phase == .done)
        hzExpect(opened == ["https://coord.example.com/oidc/start/n-abc"])
        hzExpect(backend.calls == ["up", "login_poll"])
    }

    /// 登录失败（链接过期 / IdP 拒绝）：phase=failed 且可重试（reset 回 idle）。
    func testBrowserLoginFailsAndCanRetry() async {
        let backend = FakeBackend()
        backend.upOutcome = .loginStarted(url: "https://coord.example.com/oidc/start/n-expired")
        backend.loginPollResult = .failed("登录链接已过期，请重新发起")
        let model = OnboardingViewModel()
        model.openURL = { _ in }

        await model.startBrowserLogin(backend: backend)

        guard case .failed(let reason) = model.phase else {
            hzFail("应为 failed，实际 \(model.phase)")
        return
        }
        hzExpect(reason.contains("过期"), "\(reason)")
        model.reset()
        hzExpect(model.phase == .idle)
    }

    /// 邀请码失败：coord 返回的原因进 failed（此处假后端抛 IpcError）。
    func testInviteFailureSurfacesCoordReason() async {
        let backend = FakeBackend()
        backend.joinError = "邀请码已过期，请向管理员重新索取"
        let model = OnboardingViewModel()

        await model.join(invite: "HZ-AAAA-BBBB", backend: backend)

        guard case .failed(let reason) = model.phase else {
            hzFail("应为 failed，实际 \(model.phase)")
        return
        }
        hzExpect(reason.contains("邀请码已过期"), "\(reason)")
        hzExpect(backend.joinInvites == ["HZ-AAAA-BBBB"])
    }

    /// 邀请码成功：join 返回注册快照 → done。
    func testInviteSuccess() async {
        let backend = FakeBackend()
        let model = OnboardingViewModel()
        await model.join(invite: "HZ-AAAA-BBBB", backend: backend)
        hzExpect(model.phase == .done)
    }

    /// coord 预填默认值；与默认相同不额外传（hzd 用注册/内置地址）。
    func testDefaultCoordPrefilled() {
        let model = OnboardingViewModel()
        hzExpect(model.coordText == OnboardingViewModel.defaultCoord)
        hzExpect(model.coordValid)
    }
}
