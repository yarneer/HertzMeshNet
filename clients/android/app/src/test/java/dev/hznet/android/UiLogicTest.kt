package dev.hznet.android

import dev.hznet.android.ui.AppState
import dev.hznet.android.ui.AppState.Phase
import dev.hznet.android.ui.DeepLink
import dev.hznet.android.ui.NodeName
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** #100：状态判定（规格 §8 表驱动）。 */
class AppStateTest {

    private fun snapshot(fields: String) = JSONObject(fields)

    private fun decide(
        consent: Boolean = true,
        snapshot: JSONObject? = snapshot("""{"registered":true,"desired_state":"up","peers":[]}"""),
        revokedAt: Long? = null,
    ) = AppState.decide(
        AppState.Input(
            vpnConsentGranted = consent,
            snapshot = snapshot,
            revokedAtMillis = revokedAt,
            nowMillis = 1_000,
        )
    )

    @Test
    fun tableDriven_firstHitWins() {
        // 1. 未授权 VPN 一票否决（即使其他条件更糟）。
        assertEquals(Phase.VPN_CONSENT_MISSING, decide(consent = false))
        // 2. 未注册（快照缺失或 registered=false）。
        assertEquals(Phase.UNREGISTERED, decide(snapshot = null))
        assertEquals(
            Phase.UNREGISTERED,
            decide(snapshot = snapshot("""{"registered":false}""")),
        )
        // 3. 需要重新登录（过期 / 吊销）。
        assertEquals(
            Phase.NEEDS_RELOGIN,
            decide(snapshot = snapshot("""{"registered":true,"expired":true,"desired_state":"up"}""")),
        )
        assertEquals(
            Phase.NEEDS_RELOGIN,
            decide(snapshot = snapshot("""{"registered":true,"revoked":true,"desired_state":"up"}""")),
        )
        // 4. 被其他 VPN 接管：onRevoke 记录在 + desired down。
        assertEquals(
            Phase.TAKEN_OVER_BY_OTHER_VPN,
            decide(
                snapshot = snapshot("""{"registered":true,"desired_state":"down"}"""),
                revokedAt = 999,
            ),
        )
        // onRevoke 记录在但 desired 已回到 up：不构成"被接管"。
        assertEquals(
            Phase.CONNECTED,
            decide(
                snapshot = snapshot("""{"registered":true,"desired_state":"up","peers":[]}"""),
                revokedAt = 999,
            ),
        )
        // 5. 已断开（无 onRevoke 记录）。
        assertEquals(
            Phase.DISCONNECTED,
            decide(snapshot = snapshot("""{"registered":true,"desired_state":"down"}""")),
        )
        // 6. 部分中转：有 relayed 对端且原因不是 punch_pending。
        assertEquals(
            Phase.PARTIALLY_RELAYED,
            decide(
                snapshot = snapshot(
                    """{"registered":true,"desired_state":"up","peers":["""
                        + """{"path":"relay","relay_reason":"no_candidates"},"""
                        + """{"path":"direct"}]}""",
                ),
            ),
        )
        // punch_pending 不算部分中转（打洞进行中）。
        assertEquals(
            Phase.CONNECTED,
            decide(
                snapshot = snapshot(
                    """{"registered":true,"desired_state":"up","peers":["""
                        + """{"path":"relay","relay_reason":"punch_pending"}]}""",
                ),
            ),
        )
        // 7. 已连接。
        assertEquals(
            Phase.CONNECTED,
            decide(snapshot = snapshot("""{"registered":true,"desired_state":"up","peers":[{"path":"direct"}]}""")),
        )
    }
}

/** #100：深链校验（https-only、不同 coord 拒绝、确认数据完整）。 */
class DeepLinkTest {

    @Test
    fun validLinkYieldsConfirmationWithDomain() {
        val verdict = DeepLink.parse(
            "hznet://join?coord=https%3A%2F%2Fcoord.example.com&invite=HZ-ABCD-EFGH",
            registeredCoord = null,
        )
        assertTrue(verdict is DeepLink.JoinLink.NeedsConfirmation)
        verdict as DeepLink.JoinLink.NeedsConfirmation
        assertEquals("https://coord.example.com", verdict.coordUrl)
        assertEquals("coord.example.com", verdict.coordDomain)
        assertEquals("HZ-ABCD-EFGH", verdict.inviteCode)
    }

    @Test
    fun nonHttpsCoordIsRejected() {
        val verdict = DeepLink.parse(
            "hznet://join?coord=http%3A%2F%2Fcoord.example.com",
            registeredCoord = null,
        )
        assertTrue(verdict is DeepLink.JoinLink.Rejected)
        assertEquals(DeepLink.Reason.NOT_HTTPS, (verdict as DeepLink.JoinLink.Rejected).reason)
    }

    @Test
    fun differentRegisteredCoordIsRejected() {
        val verdict = DeepLink.parse(
            "hznet://join?coord=https%3A%2F%2Fcoord.other.com",
            registeredCoord = "https://coord.example.com",
        )
        assertEquals(
            DeepLink.Reason.DIFFERENT_COORD,
            (verdict as DeepLink.JoinLink.Rejected).reason,
        )
    }

    @Test
    fun sameRegisteredCoordPasses() {
        val verdict = DeepLink.parse(
            "hznet://join?coord=https%3A%2F%2Fcoord.example.com",
            registeredCoord = "https://coord.example.com",
        )
        assertTrue(verdict is DeepLink.JoinLink.NeedsConfirmation)
    }

    @Test
    fun malformedLinksAreRejected() {
        assertTrue(
            DeepLink.parse("https://example.com/join", null) is DeepLink.JoinLink.Rejected
        )
        assertTrue(
            DeepLink.parse("hznet://other?coord=https://coord.example.com", null)
                is DeepLink.JoinLink.Rejected
        )
        assertTrue(
            DeepLink.parse("hznet://join?invite=HZ-ABCD-EFGH", null) is DeepLink.JoinLink.Rejected
        )
    }
}

/** #100：Node Name 规范化（Build.MODEL → 预填值）。 */
class NodeNameTest {
    @Test
    fun modelNormalizesToLowercaseDashed() {
        assertEquals("pixel-8", NodeName.fromModel("Pixel 8"))
        assertEquals("sm-s928b", NodeName.fromModel("SM-S928B"))
        assertEquals("mi-14-pro", NodeName.fromModel("Mi 14 Pro"))
        // 连续分隔压缩、首尾清理。
        assertEquals("huawei-mate-60", NodeName.fromModel("--Huawei_Mate.60--"))
        assertEquals("", NodeName.fromModel("!!!"))
        assertEquals("", NodeName.fromModel(null))
    }
}
