package dev.hznet.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import dev.hznet.android.engine.EngineBridge
import org.json.JSONObject

/**
 * 开机恢复（规格 §7）：已注册、Desired State 为 up、已获 VPN 同意时拉起
 * 服务；down 时保持断开。兼容"始终开启的 VPN"：系统拉起的服务路径在
 * HzNetVpnService.onStartCommand 的无 action 分支处理。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val stateDir = java.io.File(context.filesDir, "hznet")
        if (!java.io.File(stateDir, "registration.json").exists()) return
        val desired = runCatching {
            JSONObject(java.io.File(stateDir, "desired_state.json").readText())
                .optString("state")
        }.getOrDefault("up")
        val consentGranted = VpnService.prepare(context) == null
        if (desired == "up" && consentGranted) {
            val config = context
                .getSharedPreferences(HzNetVpnService.PREFS, Context.MODE_PRIVATE)
                .getString(HzNetVpnService.PREF_LAST_CONFIG, null)
                ?: EngineBridge.configJson(stateDir.path, null, null, null, null, null)
            HzNetVpnService.start(context, config)
        }
    }
}
