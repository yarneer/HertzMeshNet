import Foundation

/// `hznet://join?coord=<https URL>&invite=<code>` 深链（#88 / 规格 §6）。
/// 校验是纯函数（Swift 单测五情形）；确认框由 App 层展示——醒目显示
/// coord 域名，确认后才按邀请码路径执行。恶意链接不能把 Node 悄悄接入
/// 别人的网络。
public enum DeepLink {
    public enum Verdict: Equatable, Sendable {
        /// 可执行：待确认后按邀请码路径加入。
        case valid(coord: URL, invite: String)
        /// 已注册到同一 coord：不执行，App 显示「已加入」信息提示。
        case alreadyJoined(coord: URL)
        /// 拒绝 + 原因（展示给用户）。
        case invalid(reason: String)
    }

    /// 校验规则（规格 §6 / #88 验收）：
    /// 1. scheme 必须是 `hznet`，动作（host）必须是 `join`；
    /// 2. coord 参数必须是 `https://` URL（拒绝 http——深链来自外部，
    ///    只信 TLS；本地开发用引导窗手输）；
    /// 3. invite 参数非空；
    /// 4. 本机已注册到**不同** coord（比较 scheme+host）时拒绝，提示改用
    ///    CLI；同一 coord 提示已加入（invalid 的特例文案由调用方换为信息
    ///    提示，这里仍拒绝执行）；
    /// 5. 参数缺失 / 格式错误拒绝并说明。
    public static func parse(
        url: URL,
        registeredCoord: String?
    ) -> Verdict {
        guard url.scheme?.lowercased() == "hznet" else {
            return .invalid(reason: "不是 hznet:// 链接")
        }
        guard url.host?.lowercased() == "join" else {
            return .invalid(reason: "未知动作：\(url.host ?? "")")
        }
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return .invalid(reason: "链接格式无法解析")
        }
        let query = components.queryItems ?? []
        guard let coordRaw = query.first(where: { $0.name == "coord" })?.value,
              !coordRaw.isEmpty else {
            return .invalid(reason: "缺少 coord 参数")
        }
        guard let invite = query.first(where: { $0.name == "invite" })?.value,
              !invite.trimmingCharacters(in: .whitespaces).isEmpty else {
            return .invalid(reason: "缺少 invite 参数")
        }
        guard let coord = URL(string: coordRaw),
              let scheme = coord.scheme?.lowercased(), scheme == "https",
              let host = coord.host, !host.isEmpty else {
            return .invalid(reason: "coord 必须是 https:// 地址（实际：\(coordRaw)）")
        }
        if let registeredCoord, !registeredCoord.isEmpty,
           let current = URL(string: registeredCoord),
           let currentHost = current.host {
            // 同一 coord 判定比较 scheme+host+port（端口不同即不同部署）。
            let sameHost = currentHost.lowercased() == host.lowercased()
            let samePort = current.port == coord.port
            let sameScheme = (current.scheme?.lowercased() ?? "https")
                == (coord.scheme?.lowercased() ?? "https")
            if !(sameHost && samePort && sameScheme) {
                // 已注册到别的网络：不给换（重新加入需 CLI 删除注册）。
                return .invalid(
                    reason: "本机已加入 \(currentHost) 的网络；要加入别的网络请先用命令行删除注册（hz node delete）"
                )
            }
            return .alreadyJoined(coord: coord)
        }
        return .valid(coord: coord, invite: invite)
    }

    /// 已注册到同一 coord：不执行，信息提示。
    public static func alreadyJoinedMessage(coord: URL) -> String {
        "本机已加入 \(coord.host ?? "") 的网络"
    }

    /// 确认框文案：醒目显示域名（#88 验收）。
    public static func confirmMessage(coord: URL, invite: String) -> String {
        let masked = invite.count > 8
            ? "\(invite.prefix(4))…\(invite.suffix(4))"
            : invite
        return """
        即将加入网络
        \(coord.host ?? "")
        邀请码 \(masked)
        """
    }
}
