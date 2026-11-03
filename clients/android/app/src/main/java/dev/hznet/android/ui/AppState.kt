package dev.hznet.android.ui

import org.json.JSONObject

/**
 * 七态状态判定（规格 §8，自上而下取第一条命中）。纯函数：输入是订阅
 * 快照（引擎 `subscribe` 的 status 全量）+ 平台侧输入（VPN 同意、最近一次
 * onRevoke 时刻），输出唯一状态。表驱动单元测试锁定。
 */
object AppState {

    enum class Phase {
        /** 尚未取得 VpnService.prepare 同意。 */
        VPN_CONSENT_MISSING,

        /** 快照 registered=false → 进入引导。 */
        UNREGISTERED,

        /** expired 或 revoked：需要重新登录（revoked 提示需 Admin 处理）。 */
        NEEDS_RELOGIN,

        /** 最近一次断开原因为 onRevoke 且 Desired State 为 down。 */
        TAKEN_OVER_BY_OTHER_VPN,

        /** Desired State 为 down。 */
        DISCONNECTED,

        /** 有 Relayed Path 对端，原因不是 punch_pending。 */
        PARTIALLY_RELAYED,

        /** 以上皆否。 */
        CONNECTED,
    }

    data class Input(
        val vpnConsentGranted: Boolean,
        val snapshot: JSONObject?,
        /** 最近一次 onRevoke 的时刻（毫秒）；null = 从未。 */
        val revokedAtMillis: Long?,
        /** 评估"被接管"的当前时刻（测试注入）。 */
        val nowMillis: Long = System.currentTimeMillis(),
    )

    fun decide(input: Input): Phase {
        if (!input.vpnConsentGranted) return Phase.VPN_CONSENT_MISSING
        val snapshot = input.snapshot ?: return Phase.UNREGISTERED
        if (!snapshot.optBoolean("registered", false)) return Phase.UNREGISTERED
        // 需要重新登录：过期或吊销（身份救不回来，文案区分）。
        if (snapshot.optBoolean("expired", false) || snapshot.optBoolean("revoked", false)) {
            return Phase.NEEDS_RELOGIN
        }
        // 被其他 VPN 接管：最近一次断开原因是 onRevoke（服务记录）且当前
        // Desired State 仍为 down（onRevoke 流程写下的）。
        val revoked = input.revokedAtMillis
        if (revoked != null && snapshot.optString("desired_state") == "down") {
            return Phase.TAKEN_OVER_BY_OTHER_VPN
        }
        if (snapshot.optString("desired_state") == "down") return Phase.DISCONNECTED
        val peers = snapshot.optJSONArray("peers")
        if (peers != null) {
            for (i in 0 until peers.length()) {
                val peer = peers.optJSONObject(i) ?: continue
                if (peer.optString("path") == "relay" &&
                    peer.optString("relay_reason") != "punch_pending"
                ) {
                    return Phase.PARTIALLY_RELAYED
                }
            }
        }
        return Phase.CONNECTED
    }

    fun label(phase: Phase): String = when (phase) {
        Phase.VPN_CONSENT_MISSING -> "未授权 VPN"
        Phase.UNREGISTERED -> "未注册"
        Phase.NEEDS_RELOGIN -> "需要重新登录"
        Phase.TAKEN_OVER_BY_OTHER_VPN -> "被其他 VPN 接管"
        Phase.DISCONNECTED -> "已断开"
        Phase.PARTIALLY_RELAYED -> "部分中转"
        Phase.CONNECTED -> "已连接"
    }
}
