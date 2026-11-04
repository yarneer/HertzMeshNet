package dev.hznet.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.app.NotificationCompat
import dev.hznet.android.engine.EngineBridge
import dev.hznet.android.engine.HzNetPlatform
import dev.hznet.android.engine.SnapshotSink
import dev.hznet.android.ui.AppModel
import dev.hznet.android.ui.LoginFlow
import dev.hznet.android.ui.MainActivity
import org.json.JSONObject

/**
 * HzNet 的 VpnService（ADR-0012：引擎运行在本进程内）：
 * - 前台服务 + 常驻通知（点击打开 App）；连接期间保持前台。
 * - 首次 `up` 前 `VpnService.prepare` 由 Activity 完成（一次性授权）。
 * - Desired State 持久化在引擎（state_dir），重启后按其恢复。
 * - 兼容"始终开启的 VPN"：系统拉起（无 action 的 onStartCommand）时按
 *   已注册状态启动数据面；Desired State 为 down 时遵从系统意图启动并
 *   写回 up（规格 §7）。
 * - `onRevoke`（被其他 VPN 抢占）：停数据面、Desired State 写 down、
 *   记录时刻供 UI 显示"被其他 VPN 接管"并发通知。
 */
class HzNetVpnService : VpnService() {

    companion object {
        const val ACTION_START = "dev.hznet.android.action.START"
        const val ACTION_STOP = "dev.hznet.android.action.STOP"
        const val EXTRA_CONFIG = "config_json"
        private const val CHANNEL_STATUS = "hznet-status"
        private const val NOTIFICATION_ID = 1
        const val PREFS = "hznet"
        const val PREF_LAST_CONFIG = "last_config_json"

        /** 最近一次 onRevoke 的时刻（毫秒）；UI 七态判定"被其他 VPN 接管"的输入。 */
        @Volatile
        var lastRevokeAtMillis: Long? = null
            private set

        /**
         * 待消费的邀请码（Activity 收集输入 → 服务进程内 up 注册）。
         * `hznet://join` 深链走同一通道。
         */
        @Volatile
        var pendingInvite: String? = null

        /** 待发起的浏览器登录（引导页选择"浏览器登录"时带上 coord 地址）。 */
        @Volatile
        var pendingBrowserLogin: String? = null

        /** 拉起服务（连接开关 on）。 */
        fun start(context: Context, configJson: String) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putString(PREF_LAST_CONFIG, configJson).apply()
            val intent = Intent(context, HzNetVpnService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_CONFIG, configJson)
            context.startForegroundService(intent)
        }

        /** 停止（连接开关 off）：Desired State 由引擎持久化为 down。 */
        fun stop(context: Context) {
            context.startService(
                Intent(context, HzNetVpnService::class.java).setAction(ACTION_STOP)
            )
        }
    }

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                requestDown()
                EngineBridge.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> startEngine(intent.getStringExtra(EXTRA_CONFIG) ?: lastConfig())
            else -> {
                // 无显式 intent：系统"始终开启的 VPN"拉起。已注册就启动，
                // Desired State 为 down 时遵从系统意图启动并写回 up（规格 §7）。
                if (isRegistered()) {
                    startEngine(lastConfig(), honorSystemIntent = true)
                } else {
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    private fun lastConfig(): String =
        getSharedPreferences(PREFS, MODE_PRIVATE).getString(PREF_LAST_CONFIG, null)
            ?: EngineBridge.configJson(stateDir(), null, null, null, null, null)

    private fun startEngine(configJson: String, honorSystemIntent: Boolean = false) {
        startForeground(NOTIFICATION_ID, buildNotification("HzNet 连接中…"))
        val started = EngineBridge.start(configJson, HzNetPlatform(this))
        if (!started) {
            stopSelf()
            return
        }
        // 引导路径的注册：邀请码 up（Activity 传入）。已注册时引擎幂等恢复。
        val hadInvite = pendingInvite != null
        pendingInvite?.let { invite ->
            pendingInvite = null
            EngineBridge.request(
                """{"method":"up","params":{"invite_code":"$invite"}}"""
            )
        }
        // 浏览器登录：up 拿 login_url → Custom Tabs 打开 → 轮询 login_poll →
        // 完成后把 App 切回前台（规格 §8）。
        val hadBrowserLogin = pendingBrowserLogin != null
        pendingBrowserLogin?.let { coord ->
            pendingBrowserLogin = null
            startBrowserLogin(coord)
        }
        // 普通开关 / 系统"始终开启"拉起：Desired State 为 down 时恢复数据面
        // （已注册的 up 是幂等恢复：不重新注册、不轮换密钥，只拉数据面并写 up）。
        // 引导路径（邀请码 / 浏览器登录）自带 up，不在此重复发。
        if (!hadInvite && !hadBrowserLogin && EngineBridge.desiredState() == "down") {
            EngineBridge.request("""{"method":"up","params":{}}""")
        }
        watchPhysicalNetwork()
        subscribeStatus()
        // 更新检查（#102）：记录 coord 基地址并排每日 manifest 检查；
        // 到期提醒的通知渠道（#101）。
        runCatching {
            val coord = JSONObject(configJson).optString("coord_addr")
            if (coord.isNotBlank()) {
                dev.hznet.android.update.Updater.noteCoordBase(this, coord)
            }
        }
        dev.hznet.android.update.Updater.createChannel(this)
        dev.hznet.android.update.Updater.schedule(this)
        dev.hznet.android.notify.ExpiryNotifier.createChannel(this)
    }

    private var loginFlow: LoginFlow? = null

    private fun startBrowserLogin(coordAddr: String) {
        loginFlow?.cancel()
        loginFlow = LoginFlow(
            backend = dev.hznet.android.backend.JniBackend(),
            onStarted = { loginUrl ->
                CustomTabsIntent.Builder().build().launchUrl(this, android.net.Uri.parse(loginUrl))
            },
            onFinished = { outcome ->
                if (outcome == LoginFlow.Outcome.COMPLETED) {
                    // 登录完成：切回前台（clearTop 复用单实例 Activity）。
                    startActivity(
                        Intent(this, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
                    )
                }
            },
        )
        loginFlow?.begin(coordAddr)
    }

    /** 物理网络变化（Wi-Fi ↔ 蜂窝等）→ onNetworkChanged 驱动重绑（30 秒内恢复）。 */
    private fun watchPhysicalNetwork() {
        if (networkCallback != null) return
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                pushDnsServers(manager, network)
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                pushDnsServers(manager, network)
            }
        }
        val request = android.net.NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        manager.registerNetworkCallback(request, callback)
        networkCallback = callback
    }

    private fun pushDnsServers(manager: ConnectivityManager, network: Network) {
        val link = manager.getLinkProperties(network) ?: return
        val servers = link.dnsServers.map { it.hostAddress }.filterNotNull()
        EngineBridge.onNetworkChanged(servers.toString())
    }

    /** 订阅引擎快照：更新常驻通知 + AppModel（UI 的唯一数据源）+ 到期重排。 */
    private fun subscribeStatus() {
        EngineBridge.subscribe(SnapshotSink { snapshotJson ->
            runCatching {
                val response = JSONObject(snapshotJson)
                val result = response.optJSONObject("result") ?: return@SnapshotSink
                AppModel.publish(result)
                updateNotification(statusLine(result))
                // 到期提醒（#101）：expires_at 变化时 WorkManager REPLACE 重排；
                // VPN 关闭时也能触发（不依赖引擎运行）。
                val expiresAt = if (result.has("expires_at_unix")) {
                    result.optLong("expires_at_unix", 0)
                } else {
                    0
                }
                dev.hznet.android.notify.ExpiryNotifier.reschedule(this, expiresAt.takeIf { it > 0 })
            }
        })
    }

    private fun statusLine(snapshot: JSONObject): String {
        if (!snapshot.optBoolean("registered")) return "未注册"
        if (snapshot.optBoolean("revoked")) return "已吊销"
        if (snapshot.optBoolean("expired")) return "需要重新登录"
        return if (snapshot.optString("desired_state") == "up") {
            "已连接 · ${snapshot.optString("name")}"
        } else {
            "已断开 · ${snapshot.optString("name")}"
        }
    }

    private fun requestDown() {
        // 引擎 down：拆数据面并把 Desired State 持久化为 down（#81 语义）。
        runCatching { EngineBridge.request("""{"method":"down","params":{}}""") }
    }

    /** 被其他 VPN 抢占：停数据面、Desired State 写 down、通知（规格 §7）。 */
    override fun onRevoke() {
        lastRevokeAtMillis = System.currentTimeMillis()
        AppModel.noteRevoked()
        requestDown()
        EngineBridge.stop()
        stopForeground(STOP_FOREGROUND_REMOVE)
        notifyRevoked()
        stopSelf()
    }

    private fun notifyRevoked() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(2, buildNotification("HzNet 已被其他 VPN 接管",
            "Android 同一时间只允许一个 VPN。需要 HzNet 时请断开另一个 VPN 后重连。"))
    }

    private fun isRegistered(): Boolean =
        java.io.File(stateDir(), "registration.json").exists()

    private fun stateDir(): String = java.io.File(filesDir, "hznet").path

    private fun createChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_STATUS,
                "HzNet 状态",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "连接状态常驻通知" }
        )
    }

    private fun buildNotification(text: String): Notification = buildNotification("HzNet", text)

    private fun buildNotification(title: String, text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(open)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    override fun onDestroy() {
        loginFlow?.cancel()
        networkCallback?.let {
            runCatching {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            }
        }
        networkCallback = null
        super.onDestroy()
    }
}
