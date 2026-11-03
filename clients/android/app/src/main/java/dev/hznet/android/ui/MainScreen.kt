package dev.hznet.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.hznet.android.backend.JniBackend
import dev.hznet.android.engine.EngineBridge
import dev.hznet.android.vpn.HzNetVpnService
import org.json.JSONObject

/** 屏幕路由（单 Activity 内部状态）。 */
private enum class Screen { MAIN, ONBOARDING, SETTINGS }

/**
 * #100 完整界面：全部由 `subscribe` 快照驱动（AppModel），后端经
 * [dev.hznet.android.backend.HzBackend] 接口访问（JniBackend 唯一实现）。
 */
@Composable
fun HzNetApp(deepLinkInput: String?) {
    val context = LocalContext.current
    var screen by remember { mutableStateOf(Screen.MAIN) }
    var pendingDeepLink by remember { mutableStateOf(deepLinkInput ?: AppModel.pendingDeepLink) }
    // 运行中到达的深链（onNewIntent）。
    AppModel.pendingDeepLink?.let { link ->
        pendingDeepLink = link
        AppModel.consumeDeepLink()
    }

    // 未注册 → 引导（快照未到时按注册文件判断，见 shouldOnboard）。
    val snapshot = AppModel.snapshot
    if (screen == Screen.MAIN && snapshot?.optBoolean("registered") == false) {
        screen = Screen.ONBOARDING
    }

    // 深链确认框（一律醒目显示 coord 域名；校验规则见 DeepLink）。
    pendingDeepLink?.let { link ->
        val verdict = DeepLink.parse(
            link,
            snapshot?.optString("coord_addr")?.takeIf { it.isNotBlank() },
        )
        when (verdict) {
            is DeepLink.JoinLink.NeedsConfirmation -> AlertDialog(
                onDismissRequest = { pendingDeepLink = null },
                title = { Text("加入 HzNet 网络？", fontWeight = FontWeight.Bold) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("即将连接 Coordination Server：")
                        Text(
                            verdict.coordDomain,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                        )
                        verdict.inviteCode?.let { Text("使用邀请码 ${it.take(8)}…（加入后生效）") }
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        pendingDeepLink = null
                        HzNetVpnService.pendingInvite = verdict.inviteCode
                        HzNetVpnService.start(
                            context,
                            EngineBridge.configJson(
                                java.io.File(context.filesDir, "hznet").path,
                                verdict.coordUrl, null, null, null, null,
                            ),
                        )
                    }) { Text("加入") }
                },
                dismissButton = {
                    TextButton(onClick = { pendingDeepLink = null }) { Text("取消") }
                },
            )
            is DeepLink.JoinLink.Rejected -> AlertDialog(
                onDismissRequest = { pendingDeepLink = null },
                title = { Text("无法打开链接") },
                text = { Text(verdict.reason.message) },
                confirmButton = {
                    TextButton(onClick = { pendingDeepLink = null }) { Text("知道了") }
                },
            )
        }
    }

    // 私人 DNS 严格模式提示（一次）：Magic DNS 可能失效（规格 §5.2）。
    PrivateDnsHint(context)

    when (screen) {
        Screen.MAIN -> MainScreen(
            onOpenSettings = { screen = Screen.SETTINGS },
            onOpenOnboarding = { screen = Screen.ONBOARDING },
        )
        Screen.ONBOARDING -> OnboardingScreen(onDone = { screen = Screen.MAIN })
        Screen.SETTINGS -> SettingsScreen(onBack = { screen = Screen.MAIN })
    }
}

@Composable
private fun MainScreen(onOpenSettings: () -> Unit, onOpenOnboarding: () -> Unit) {
    val context = LocalContext.current
    val snapshot = AppModel.snapshot
    val phase = AppState.decide(
        AppState.Input(
            vpnConsentGranted = remember { VpnService.prepare(context) == null },
            snapshot = snapshot,
            revokedAtMillis = AppModel.revokedAtMillis,
        )
    )
    var connected by remember { mutableStateOf(snapshot?.optString("desired_state") == "up") }

    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("HzNet", fontSize = 24.sp, fontWeight = FontWeight.Bold)
            TextButton(onClick = onOpenSettings) { Text("设置") }
        }
        Text(AppState.label(phase), fontSize = 18.sp, color = MaterialTheme.colorScheme.primary)

        if (phase == AppState.Phase.UNREGISTERED) {
            Button(onClick = onOpenOnboarding, modifier = Modifier.fillMaxWidth()) {
                Text("开始引导")
            }
            return@Column
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(if (connected) "已连接" else "已断开", fontSize = 16.sp)
            Switch(
                checked = connected,
                onCheckedChange = { want ->
                    if (want) {
                        if (VpnService.prepare(context) != null) {
                            VpnService.prepare(context)?.let(context::startActivity)
                            return@Switch
                        }
                        HzNetVpnService.start(
                            context,
                            context.getSharedPreferences(HzNetVpnService.PREFS, Context.MODE_PRIVATE)
                                .getString(HzNetVpnService.PREF_LAST_CONFIG, null)
                                ?: EngineBridge.configJson(
                                    java.io.File(context.filesDir, "hznet").path,
                                    null, null, null, null, null,
                                ),
                        )
                    } else {
                        HzNetVpnService.stop(context)
                    }
                    connected = want
                },
            )
        }

        snapshot?.let { NodeIdentityCard(context, it) }
        snapshot?.let { PeerList(context, it) }

        OutlinedButton(
            onClick = { exportDiagnostics(context, snapshot) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("导出诊断包") }
    }
}

/** 诊断包（#101）：引擎 diagnostics + 元信息 → zip → 系统分享面板。 */
private fun exportDiagnostics(context: Context, snapshot: JSONObject?) {
    val diagnostics = runCatching {
        val reply = JSONObject(EngineBridge.request("""{"method":"diagnostics","params":{}}"""))
        reply.optJSONObject("result") ?: JSONObject()
    }.getOrDefault(JSONObject())
    val power = context.getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
    val zip = dev.hznet.android.diagnostics.DiagnosticsExport.buildZip(
        diagnostics,
        dev.hznet.android.diagnostics.DiagnosticsExport.Meta(
            appVersion = runCatching {
                context.packageManager.getPackageInfo(context.packageName, 0).versionName
            }.getOrNull() ?: "0.0.0",
            androidVersion = Build.VERSION.RELEASE ?: "?",
            model = Build.MODEL ?: "?",
            privateDnsMode = runCatching {
                Settings.Global.getString(context.contentResolver, Settings.Global.PRIVATE_DNS_MODE)
            }.getOrNull() ?: "off",
            batteryWhitelisted = power.isIgnoringBatteryOptimizations(context.packageName),
        ),
    )
    val node = snapshot?.optString("name").takeUnless { it.isNullOrBlank() } ?: "node"
    val file = java.io.File(context.cacheDir, "${dev.hznet.android.diagnostics.DiagnosticsExport.fileName(node, System.currentTimeMillis())}.zip")
    file.writeBytes(zip)
    val share = file.let {
        android.content.Intent(android.content.Intent.ACTION_SEND).apply {
            type = "application/zip"
            putExtra(
                android.content.Intent.EXTRA_STREAM,
                androidx.core.content.FileProvider.getUriForFile(
                    context, "${context.packageName}.files", it
                )
            )
            addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }
    context.startActivity(
        android.content.Intent.createChooser(share, "分享 HzNet 诊断包")
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
    )
}

@Composable
private fun NodeIdentityCard(context: Context, snapshot: JSONObject) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            CopyableText(context, "Node Name", snapshot.optString("name"))
            CopyableText(context, "Node Address", snapshot.optString("ipv4"))
        }
    }
}

@Composable
private fun PeerList(context: Context, snapshot: JSONObject) {
    val peers = snapshot.optJSONArray("peers") ?: return
    Text("对端（${peers.length()}）", fontWeight = FontWeight.Bold)
    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items((0 until peers.length()).toList()) { i ->
            val peer = peers.optJSONObject(i) ?: return@items
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        copy(
                            context,
                            "${peer.optString("name")}.hznet.internal",
                        )
                    },
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(peer.optString("name"), fontWeight = FontWeight.Bold)
                    val path = peer.optString("path", "—")
                    val reason = peer.optString("relay_reason").takeIf { it.isNotBlank() }
                    Text(
                        when {
                            path == "direct" -> "Direct 直连"
                            path == "relay" && reason != null -> "Relayed 中转（$reason）"
                            path == "relay" -> "Relayed 中转"
                            else -> "路径未知"
                        }
                    )
                    peer.optString("endpoint").takeIf { it.isNotBlank() }?.let { Text(it, fontSize = 12.sp) }
                }
            }
        }
    }
}

@Composable
private fun CopyableText(context: Context, label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { copy(context, value) },
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Bold)
    }
}

private fun copy(context: Context, text: String) {
    val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    manager.setPrimaryClip(ClipData.newPlainText("HzNet", text))
}

@Composable
private fun PrivateDnsHint(context: Context) {
    var shown by remember { mutableStateOf(false) }
    if (shown) return
    val prefs = context.getSharedPreferences("hznet", Context.MODE_PRIVATE)
    if (prefs.getBoolean("private_dns_hint_done", false)) return
    val strict = runCatching {
        Settings.Global.getString(context.contentResolver, Settings.Global.PRIVATE_DNS_MODE)
    }.getOrNull() == "strict"
    if (!strict) return
    AlertDialog(
        onDismissRequest = {},
        title = { Text("检测到私人 DNS 严格模式") },
        text = { Text("Magic DNS（*.hznet.internal）可能失效。可在系统设置改用自动模式，或继续使用 Node Address。") },
        confirmButton = {
            TextButton(onClick = {
                prefs.edit().putBoolean("private_dns_hint_done", true).apply()
                shown = true
            }) { Text("知道了") }
        },
    )
}
