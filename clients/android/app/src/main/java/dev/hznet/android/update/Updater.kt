package dev.hznet.android.update

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.hznet.android.ui.MainActivity
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * App 内更新的落地（规格 §9）：
 * - [schedule] 每日检查一次 manifest（WorkManager 周期任务，充电/联网时）；
 * - [checkNow] 设置页"检查更新"即时检查；
 * - 有新版本 → "有新版本"通知（同时覆盖 coord 提示版本过旧的情形）；
 * - [downloadAndInstall] 确认后下载到 cache → sha256 校验（失败丢弃并
 *   提示）→ 交系统安装器（REQUEST_INSTALL_PACKAGES）。不静默升级。
 */
object Updater {
    private const val CHANNEL = "hznet-update"
    private const val WORK_NAME = "hznet-daily-update-check"
    const val NOTIFICATION_ID = 103

    fun createChannel(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "新版本", NotificationManager.IMPORTANCE_DEFAULT)
        )
    }

    fun schedule(context: Context) {
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<DailyCheckWorker>(1, TimeUnit.DAYS)
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .build(),
        )
    }

    /** 即时检查；返回 null = 无更新或失败（失败静默，设置页展示空态）。 */
    fun checkNow(context: Context, currentVersion: String): UpdateCheck.Manifest? {
        val coord = coordBaseUrl(context) ?: return null
        val manifest = fetchManifest(coord) ?: return null
        if (!UpdateCheck.isNewer(currentVersion, manifest.version)) return null
        notifyNewVersion(context, manifest.version)
        return manifest
    }

    private fun coordBaseUrl(context: Context): String? {
        val prefs = context.getSharedPreferences("hznet", Context.MODE_PRIVATE)
        return prefs.getString("coord_base", null)
    }

    /** 设置页连接成功后记录（https://host，拼 /dl/… 用）。 */
    fun noteCoordBase(context: Context, coordAddr: String) {
        val base = runCatching {
            val uri = java.net.URI(coordAddr)
            "${uri.scheme}://${uri.host}${if (uri.port != -1) ":${uri.port}" else ""}"
        }.getOrNull() ?: return
        context.getSharedPreferences("hznet", Context.MODE_PRIVATE)
            .edit().putString("coord_base", base).apply()
    }

    private fun fetchManifest(base: String): UpdateCheck.Manifest? = runCatching {
        val connection = URL("$base/dl/manifest.json").openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        if (connection.responseCode != 200) return null
        UpdateCheck.parseManifest(connection.inputStream.readBytes().decodeToString())
    }.getOrNull()

    private fun notifyNewVersion(context: Context, version: String) {
        val open = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(
            NOTIFICATION_ID,
            NotificationCompat.Builder(context, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("HzNet 有新版本")
                .setContentText("版本 $version 可用，打开 App 确认升级（升级保留 Node 身份）")
                .setContentIntent(open)
                .setAutoCancel(true)
                .build(),
        )
    }

    /** 确认升级：下载到 cacheDir → 校验 → 系统安装器。返回错误文案（null=已交安装器）。 */
    fun downloadAndInstall(context: Context, currentVersion: String): String? {
        val coord = coordBaseUrl(context) ?: return "尚未连接 Coordination Server"
        val manifest = fetchManifest(coord) ?: return "无法获取更新清单"
        if (!UpdateCheck.isNewer(currentVersion, manifest.version)) return "已是最新版本"
        val entry = UpdateCheck.apkEntry(manifest) ?: return "服务器未提供 Android 安装包"
        val bytes = runCatching {
            val connection = URL("$coord/dl/${entry.path}").openConnection() as HttpURLConnection
            connection.connectTimeout = 15_000
            connection.readTimeout = 60_000
            if (connection.responseCode != 200) return "下载失败（HTTP ${connection.responseCode}）"
            connection.inputStream.readBytes()
        }.getOrNull() ?: return "下载失败"
        if (!UpdateCheck.sha256Matches(bytes, entry.sha256)) {
            return "安装包校验失败（sha256 不匹配），已丢弃"
        }
        val file = File(context.cacheDir, "hznet-${manifest.version}.apk")
        file.writeBytes(bytes)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(
                androidx.core.content.FileProvider.getUriForFile(
                    context, "${context.packageName}.files", file
                ),
                "application/vnd.android.package-archive"
            )
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        return null
    }
}

/** 每日 manifest 检查（有新版本 → 通知）。 */
class DailyCheckWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val version = runCatching {
            applicationContext.packageManager
                .getPackageInfo(applicationContext.packageName, 0).versionName
        }.getOrNull() ?: return Result.success()
        Updater.checkNow(applicationContext, version ?: "0.0.0")
        return Result.success()
    }
}
