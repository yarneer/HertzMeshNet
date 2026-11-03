import Foundation

/// 系统通知（#89 / 规格 §5）：只在需要行动时打扰，共四种；对端上下线
/// 不通知。判定与去重是纯函数（假后端 + 快照序列表驱动测试）。
public enum AppNotification: Equatable, Sendable {
    /// 距身份到期 3 天（提醒）。
    case expiresIn3Days
    /// 距到期 1 天（带「重新登录」动作）。
    case expiresIn1Day
    /// 其他 VPN 工具接管导致 HzNet 路由失效。
    case vpnConflict
    /// coord 提示版本过旧（behind / at_min）。
    case versionOutdated(String)
    /// 动作失败的非规格提示（内部错误反馈，不占四种配额）。
    case actionFailed(message: String)

    public var identifier: String {
        switch self {
        case .expiresIn3Days: return "expires-3d"
        case .expiresIn1Day: return "expires-1d"
        case .vpnConflict: return "vpn-conflict"
        case .versionOutdated: return "version-outdated"
        case .actionFailed: return "action-failed"
        }
    }

    public var title: String {
        switch self {
        case .expiresIn3Days: return "HzNet 身份将在 3 天内到期"
        case .expiresIn1Day: return "HzNet 身份将在 1 天内到期"
        case .vpnConflict: return "HzNet 路由被其他 VPN 工具干扰"
        case .versionOutdated(let hint): return "hzd 版本过旧（\(hint)）"
        case .actionFailed: return "操作失败"
        }
    }

    public var body: String {
        switch self {
        case .expiresIn3Days: return "到期后无法通信；点菜单栏图标，重新登录可续期。"
        case .expiresIn1Day: return "点「重新登录」在浏览器完成续期。"
        case .vpnConflict: return "检测到路由被其他 VPN 工具占用并已自动恢复；建议在该工具中排除 HzNet 地址段。"
        case .versionOutdated: return "运行 brew upgrade hznet 或联系管理员升级后再接入。"
        case .actionFailed(let message): return message
        }
    }
}

/// 通知触发与去重引擎（#89 纯逻辑）。
/// 同一到期点只发一次；条件消失后再成立可再发。对端变化永不触发。
public struct NotificationEngine: Sendable {
    /// 上一次快照的冲突 / 版本提示在场状态：从无到有才发；从有到无时
    /// 清除记录，允许再次出现时重发。
    private var conflictWasPresent = false
    private var versionHintWasPresent = false
    /// 已通知过的到期时刻（3 天 / 1 天各记一次）。
    private var notified3Days: Set<Int64> = []
    private var notified1Day: Set<Int64> = []

    public init() {}

    /// 评估一份快照，返回此刻应发出的通知（通常 0 或 1 条）。
    /// `now` 注入以便测试 3 天 / 1 天触发时点。
    public mutating func evaluate(
        snapshot: StatusSnapshot,
        now: Date
    ) -> [AppNotification] {
        var pending: [AppNotification] = []

        // ---- 到期：距 expires_at 3 天 / 1 天（#89）----
        if let expiresAt = snapshot.expiresAt {
            let remaining = expiresAt.timeIntervalSince(now)
            let expiryKey = Int64(expiresAt.timeIntervalSince1970)
            if remaining > 0 {
                if remaining <= 3 * 86_400 {
                    if !notified3Days.contains(expiryKey) {
                        notified3Days.insert(expiryKey)
                        pending.append(.expiresIn3Days)
                    }
                }
                if remaining <= 86_400 {
                    if !notified1Day.contains(expiryKey) {
                        notified1Day.insert(expiryKey)
                        pending.append(.expiresIn1Day)
                    }
                }
            }
            // 续期后到期点变化：新 key 天然可发；旧 key 留在集合里无害。
        }

        // ---- VPN 冲突：修复记录从无到有（#86 同一信号，15 分钟时效）----
        let conflictPresent = snapshot.diagnostics?.vpnConflict(asOf: now) == true
        if conflictPresent && !conflictWasPresent {
            pending.append(.vpnConflict)
        }
        if !conflictPresent {
            // 条件消失：清除在场记忆，再次出现可再发。
            conflictWasPresent = false
        } else {
            conflictWasPresent = true
        }

        // ---- 版本过旧：coord 的 version_hint 从空到非空（#89）----
        let hint = snapshot.versionHint ?? ""
        let hintPresent = hint == "behind" || hint == "at_min"
        if hintPresent && !versionHintWasPresent {
            pending.append(.versionOutdated(hint))
        }
        versionHintWasPresent = hintPresent

        return pending
    }
}
