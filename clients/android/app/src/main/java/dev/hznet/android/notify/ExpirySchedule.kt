package dev.hznet.android.notify

/**
 * 到期提醒的排程（规格 §8）：身份到期前 3 天与 1 天各一次；1 天档带
 * "重新登录"直达登录流程。`expires_at` 变化时整体重排（WorkManager
 * UniqueWork REPLACE）。纯函数——时点与重排由单元测试锁定（#101）。
 */
object ExpirySchedule {

    /** 提醒档位；id 供通知渠道区分（1 天档带"重新登录"动作）。 */
    enum class Tier { THREE_DAYS, ONE_DAY }

    data class Reminder(val tier: Tier, val delayMillis: Long)

    private const val DAY_MILLIS: Long = 24 * 60 * 60 * 1000

    /**
     * 给定到期时刻与当前时刻，算出应排的提醒（相对延迟 ≥ 0）。
     * 已过期或窗口已过（如距到期不足 1 天时只剩 1 天档）不排。
     * 排序保证 3 天档在前。
     */
    fun reminders(expiresAtMillis: Long, nowMillis: Long): List<Reminder> {
        if (expiresAtMillis <= 0) return emptyList()
        val tiers = listOf(
            Reminder(Tier.THREE_DAYS, expiresAtMillis - 3 * DAY_MILLIS - nowMillis),
            Reminder(Tier.ONE_DAY, expiresAtMillis - DAY_MILLIS - nowMillis),
        )
        return tiers.filter { it.delayMillis > 0 }.sortedBy { it.delayMillis }
    }

    /** 排程指纹：expires_at 变化（或档位集变化）时 WorkManager REPLACE 重排。 */
    fun fingerprint(expiresAtMillis: Long, nowMillis: Long): String =
        reminders(expiresAtMillis, nowMillis).joinToString(",") {
            "${it.tier}:${it.delayMillis / 1000}"
        }
}
