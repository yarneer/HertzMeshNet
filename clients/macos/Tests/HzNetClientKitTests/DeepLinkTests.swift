import Foundation

@testable import HzNetClientKit

/// #88：深链校验纯函数五情形（验收清单逐条）。
struct DeepLinkTests {
    let valid = URL(string: "hznet://join?coord=https%3A%2F%2Fcoord.example.com&invite=HZ-AAAA-BBBB")!

    /// 正常链接：可执行，coord/invite 解析正确。
    func testValidLink() {
        let verdict = DeepLink.parse(url: valid, registeredCoord: nil)
        guard case .valid(let coord, let invite) = verdict else {
            hzFail("应为 valid：\(verdict)")
        return
        }
        hzExpect(coord.absoluteString == "https://coord.example.com")
        hzExpect(invite == "HZ-AAAA-BBBB")
        // 确认框醒目显示域名。
        hzExpect(DeepLink.confirmMessage(coord: coord, invite: invite).contains("coord.example.com"))
    }

    /// coord 不是 https：拒绝并说明。
    func testNonHttpsCoordRejected() {
        let url = URL(string: "hznet://join?coord=http%3A%2F%2Fcoord.example.com&invite=HZ-AAAA-BBBB")!
        guard case .invalid(let reason) = DeepLink.parse(url: url, registeredCoord: nil) else {
            hzFail("http coord 必须拒绝")
        return
        }
        hzExpect(reason.contains("https"), "\(reason)")
    }

    /// 已注册到不同 coord：拒绝并提示改用 CLI。
    func testRegisteredToDifferentCoordRejected() {
        guard case .invalid(let reason) = DeepLink.parse(
            url: valid, registeredCoord: "https://other.example.com"
        ) else {
            hzFail("跨网络深链必须拒绝")
        return
        }
        hzExpect(reason.contains("other.example.com"), "\(reason)")
        hzExpect(reason.contains("命令行") || reason.contains("CLI"), "\(reason)")
    }

    /// 已注册到同一 coord：不执行（alreadyJoined），App 换成信息提示。
    func testRegisteredToSameCoordIsInformational() {
        guard case .alreadyJoined(let coord) = DeepLink.parse(
            url: valid, registeredCoord: "https://coord.example.com/some/path"
        ) else {
            hzFail("同网络应返回 alreadyJoined 而不是执行加入")
        return
        }
        hzExpect(coord.host == "coord.example.com")
        // 供 App 弹「已加入」信息提示的文案。
        let informational = URL(string: "https://coord.example.com")!
        hzExpect(DeepLink.alreadyJoinedMessage(coord: informational).contains("coord.example.com"))
    }

    /// 参数缺失 / 格式错误：拒绝并说明。
    func testMissingOrMalformedParameters() {
        let noInvite = URL(string: "hznet://join?coord=https%3A%2F%2Fcoord.example.com")!
        guard case .invalid(let reasonInvite) = DeepLink.parse(url: noInvite, registeredCoord: nil) else {
            hzFail("缺 invite 必须拒绝")
        return
        }
        hzExpect(reasonInvite.contains("invite"), "\(reasonInvite)")

        let noCoord = URL(string: "hznet://join?invite=HZ-AAAA-BBBB")!
        guard case .invalid(let reasonCoord) = DeepLink.parse(url: noCoord, registeredCoord: nil) else {
            hzFail("缺 coord 必须拒绝")
        return
        }
        hzExpect(reasonCoord.contains("coord"), "\(reasonCoord)")

        let wrongScheme = URL(string: "https://join?coord=https%3A%2F%2Fx&invite=y")!
        guard case .invalid = DeepLink.parse(url: wrongScheme, registeredCoord: nil) else {
            hzFail("非 hznet scheme 必须拒绝")
        return
        }
    }
}
