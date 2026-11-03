package dev.hznet.android.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.hznet.android.engine.EngineBridge
import dev.hznet.android.vpn.HzNetVpnService

/**
 * #99 极简界面：coord 地址、邀请码、开关与状态文本（端到端连通的验收用）。
 * 完整界面（七态、对端列表、引导、深链）在 #100 落地。
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    MinimalScreen()
                }
            }
        }
    }
}

@Composable
private fun MinimalScreen() {
    val context = LocalContext.current
    var coordAddr by remember { mutableStateOf("https://coord.example.com") }
    var inviteCode by remember { mutableStateOf("") }
    var statusText by remember { mutableStateOf("HzNet 未连接") }
    var connected by remember { mutableStateOf(false) }

    androidx.compose.foundation.layout.Column(
        modifier = Modifier.padding(16.dp).fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = coordAddr,
            onValueChange = { coordAddr = it },
            label = { Text("Coordination Server 地址") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = inviteCode,
            onValueChange = { inviteCode = it },
            label = { Text("邀请码（HZ-XXXX-XXXX）") },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                if (connected) {
                    HzNetVpnService.stop(context)
                    connected = false
                    statusText = "已断开"
                } else {
                    // 首次 up 前的一次性 VPN 授权（规格 §7）：授权完成后
                    // 用户再点一次连接（完整引导流在 #100 落地）。
                    val prepare = VpnService.prepare(context)
                    if (prepare != null) {
                        context.startActivity(prepare)
                        statusText = "请在系统对话框授权 VPN 后重试"
                        return@Button
                    }
                    connect(context, coordAddr, inviteCode)
                    connected = true
                    statusText = "连接中…"
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (connected) "断开" else "连接")
        }
        Text(text = statusText)
        // 订阅快照的实时状态行。
        val snapshot = AppModel.snapshot
        if (snapshot != null) {
            Text(
                text = buildString {
                    if (snapshot.optBoolean("registered")) {
                        append(snapshot.optString("name"))
                        append(" · ")
                        append(snapshot.optString("ipv4"))
                        append(" · ")
                        append(snapshot.optString("desired_state"))
                    } else {
                        append("未注册")
                    }
                }
            )
        }
    }
}

private fun connect(context: android.content.Context, coordAddr: String, inviteCode: String) {
    val stateDir = java.io.File(context.filesDir, "hznet").path
    val config = EngineBridge.configJson(stateDir, coordAddr, null, null, null, null)
    HzNetVpnService.start(context, config)
    // 邀请码注册（up 请求由服务进程内的引擎处理）。
    if (inviteCode.isNotBlank()) {
        HzNetVpnService.pendingInvite = inviteCode.trim()
    }
}
