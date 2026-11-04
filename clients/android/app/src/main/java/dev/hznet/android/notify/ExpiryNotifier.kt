package dev.hznet.android.notify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import dev.hznet.android.ui.MainActivity
import dev.hznet.android.vpn.HzNetVpnService
import java.util.concurrent.TimeUnit

/**
 * 到期提醒的 WorkManager 落地（规格 §8）：VPN 关闭时也能触发（WorkManager
 * 不依赖引擎运行）；`expires_at` 变化时 [`reschedule`] 用 REPLACE 整体重排。
 * 1 天档通知带"重新登录"直达登录流程（打开 App 引导）。
 */
object ExpiryNotifier {
    const val CHANNEL = "hznet-expiry"
    const val WORK_NAME = "hznet-expiry-reminders"
    const val KEY_TIER = "tier"
    const val KEY_EXPIRES_AT = "expires_at"
    const val NOTIFICATION_ID_THREE_DAYS = 101
    const val NOTIFICATION_ID_ONE_DAY = 102

    fun createChannel(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "身份到期提醒", NotificationManager.IMPORTANCE_DEFAULT)
        )
    }

    /** 快照里 expires_at（unix 秒）变化时调用：整体重排。 */
    fun reschedule(context: Context, expiresAtUnixSec: Long?) {
        val manager = WorkManager.getInstance(context)
        if (expiresAtUnixSec == null || expiresAtUnixSec <= 0) {
            manager.cancelUniqueWork(WORK_NAME)
            return
        }
        val expiresAtMillis = expiresAtUnixSec * 1000
        val now = System.currentTimeMillis()
        val reminders = ExpirySchedule.reminders(expiresAtMillis, now)
        if (reminders.isEmpty()) {
            manager.cancelUniqueWork(WORK_NAME)
            return
        }
        // 链式：首个提醒触发后由 Worker 排下一个（保持顺序与剩余档位）。
        val first = reminders.first()
        manager.enqueueUniqueWork(
            WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<ExpiryWorker>()
                .setInitialDelay(first.delayMillis, TimeUnit.MILLISECONDS)
                .setInputData(
                    workDataOf(
                        KEY_TIER to first.tier.name,
                        KEY_EXPIRES_AT to expiresAtMillis,
                    )
                )
                .build(),
        )
    }
}

/** 单档提醒的执行体：发通知，然后（若还有）排下一档。 */
class ExpiryWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val expiresAtMillis = inputData.getLong(ExpiryNotifier.KEY_EXPIRES_AT, 0)
        val tier = runCatching {
            ExpirySchedule.Tier.valueOf(inputData.getString(ExpiryNotifier.KEY_TIER) ?: "")
        }.getOrNull() ?: return Result.success()

        notify(tier, expiresAtMillis)

        // 排剩余档位（1 天档）。
        val remaining = ExpirySchedule.reminders(expiresAtMillis, System.currentTimeMillis())
            .filter { it.tier != tier }
        if (remaining.isNotEmpty()) {
            val next = remaining.first()
            WorkManager.getInstance(applicationContext).enqueueUniqueWork(
                "${ExpiryNotifier.WORK_NAME}-next-${next.tier}",
                ExistingWorkPolicy.REPLACE,
                OneTimeWorkRequestBuilder<ExpiryWorker>()
                    .setInitialDelay(next.delayMillis, TimeUnit.MILLISECONDS)
                    .setInputData(
                        workDataOf(
                            ExpiryNotifier.KEY_TIER to next.tier.name,
                            ExpiryNotifier.KEY_EXPIRES_AT to expiresAtMillis,
                        )
                    )
                    .build(),
            )
        }
        return Result.success()
    }

    private fun notify(tier: ExpirySchedule.Tier, expiresAtMillis: Long) {
        val context = applicationContext
        val days = ((expiresAtMillis - System.currentTimeMillis()) / 86_400_000L).coerceAtLeast(1)
        val open = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = when (tier) {
            ExpirySchedule.Tier.THREE_DAYS -> "HzNet 身份将在 $days 天后到期"
            ExpirySchedule.Tier.ONE_DAY -> "HzNet 身份明天到期，请重新登录续期"
        }
        val notification = NotificationCompat.Builder(context, "hznet-expiry")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("HzNet 到期提醒")
            .setContentText(text)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(
            if (tier == ExpirySchedule.Tier.THREE_DAYS) {
                ExpiryNotifier.NOTIFICATION_ID_THREE_DAYS
            } else {
                ExpiryNotifier.NOTIFICATION_ID_ONE_DAY
            },
            notification,
        )
    }
}
