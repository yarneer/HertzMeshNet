package dev.hznet.android

import dev.hznet.android.diagnostics.DiagnosticsExport
import dev.hznet.android.notify.ExpirySchedule
import dev.hznet.android.notify.ExpirySchedule.Tier
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.ZipInputStream

/** #101：到期提醒时点与重排（纯函数，表驱动）。 */
class ExpiryScheduleTest {
    private val DAY = 24 * 60 * 60 * 1000L
    private val expires = 100 * DAY // 相对锚点

    @Test
    fun threeDaysAndOneDayBeforeExpiry() {
        val now = 0L
        val reminders = ExpirySchedule.reminders(expires, now)
        assertEquals(listOf(Tier.THREE_DAYS, Tier.ONE_DAY), reminders.map { it.tier })
        assertEquals(expires - 3 * DAY, now + reminders[0].delayMillis)
        assertEquals(expires - DAY, now + reminders[1].delayMillis)
    }

    @Test
    fun windowsAlreadyPastAreSkipped() {
        // 距到期只剩 2 天：3 天档已过，只排 1 天档。
        val now = expires - 2 * DAY
        val reminders = ExpirySchedule.reminders(expires, now)
        assertEquals(listOf(Tier.ONE_DAY), reminders.map { it.tier })
        // 距到期不足 1 天：都不排（到期后的提示走"需要重新登录"状态）。
        assertTrue(ExpirySchedule.reminders(expires, expires - DAY + 1).isEmpty())
        // 已过期 / 未知（0）：不排。
        assertTrue(ExpirySchedule.reminders(expires - 1, expires).isEmpty())
        assertTrue(ExpirySchedule.reminders(0, 0).isEmpty())
    }

    @Test
    fun fingerprintChangesWhenExpiryMoves() {
        val now = 0L
        val first = ExpirySchedule.fingerprint(expires, now)
        // expires_at 续期后重排（指纹变化 → WorkManager REPLACE）。
        val renewed = ExpirySchedule.fingerprint(expires + 30 * DAY, now)
        assertTrue(first != renewed)
        // 同一时刻重复计算稳定（幂等）。
        assertEquals(first, ExpirySchedule.fingerprint(expires, now))
    }
}

/** #101：诊断包结构与二次脱敏。 */
class DiagnosticsExportTest {

    @Test
    fun secretsAreRedactedInLogTail() {
        val diagnostics = JSONObject(
            """{"log_tail": [
                "auth key hznet.QWERTYUIOPASDFGHJKLZXCVBNM",
                "relay token hzrelay.AAAAABBBBCCCCDDDDAAAAA",
                "join link https://coord.example.com/oidc/start/abc123def456",
                "invite HZ-ABCD-EFGH redeemed by alice",
                "node private key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "node db-1 endpoint 203.0.113.7:51820 direct"
            ]}"""
        )
        val zip = DiagnosticsExport.buildZip(
            diagnostics,
            DiagnosticsExport.Meta("0.4.0", "14", "Pixel 8", "strict", true),
        )
        val text = unzipText(zip)
        // 私钥 / Auth Key / 邀请码 / 登录 token 不出现。
        assertFalse(text.contains("QWERTYUIOPASDFGHJKLZXCVBNM"))
        assertFalse(text.contains("AAAAABBBBCCCCDDDDAAAAA"))
        assertFalse(text.contains("abc123def456"))
        assertFalse(text.contains("HZ-ABCD-EFGH"))
        assertFalse(text.contains("0123456789abcdef"))
        // 保留排障信息。
        assertTrue(text.contains("db-1"))
        assertTrue(text.contains("203.0.113.7:51820"))
    }

    @Test
    fun zipCarriesMetadataAndFilenameShape() {
        val diagnostics = JSONObject("""{"status":{"registered":true},"log_tail":[]}""")
        val zip = DiagnosticsExport.buildZip(
            diagnostics,
            DiagnosticsExport.Meta("0.4.0", "14", "Pixel 8", "off", false),
        )
        val text = unzipText(zip)
        assertTrue(text.contains("\"app_version\": \"0.4.0\"") || text.contains("\"app_version\":\"0.4.0\""))
        assertTrue(text.contains("Pixel 8"))
        assertTrue(text.contains("\"battery_whitelisted\": false") || text.contains("\"battery_whitelisted\":false"))
        assertEquals(
            "hznet-diagnostics-pixel-8-1700000000000",
            DiagnosticsExport.fileName("Pixel 8", 1_700_000_000_000),
        )
        assertEquals(
            "hznet-diagnostics-node-0",
            DiagnosticsExport.fileName("", 0),
        )
    }

    private fun unzipText(zip: ByteArray): String {
        val builder = StringBuilder()
        ZipInputStream(zip.inputStream()).use { stream ->
            while (true) {
                val entry = stream.nextEntry ?: break
                if (!entry.isDirectory) {
                    builder.append(String(stream.readBytes()))
                    builder.append('\n')
                }
            }
        }
        return builder.toString()
    }
}
