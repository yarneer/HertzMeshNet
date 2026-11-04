package dev.hznet.android.ui

import android.content.Context
import android.net.VpnService
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.os.Build
import dev.hznet.android.engine.EngineBridge
import dev.hznet.android.vpn.HzNetVpnService

/**
 * 首次引导（规格 §8）：coord 地址（预填默认值可改）+ Node Name（预填
 * `Build.MODEL` 规范化结果可改，作为注册参数经 EngineConfig 传给 coord）
 * + 两种接入方式：浏览器登录（Custom Tabs 打开 login_url + 轮询
 * login_poll，完成后切回前台）/ 输入邀请码。无 Auth Key 输入。
 */
@Composable
fun OnboardingScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    var coordAddr by remember { mutableStateOf("https://coord.example.com") }
    var nodeName by remember { mutableStateOf(NodeName.fromModel(Build.MODEL)) }
    var inviteCode by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }

    // VPN 授权走 ActivityResult：同意后自动继续原操作，不再要求手动重点。
    var pendingAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val action = pendingAction
        pendingAction = null
        if (VpnService.prepare(context) == null) {
            action?.invoke()
        } else {
            note = if (result.resultCode == android.app.Activity.RESULT_OK) {
                "VPN 授权未完成，请重试"
            } else {
                "已拒绝 VPN 授权：HzNet 需要建立隧道才能加入，请重新点击并在系统对话框选“确定”"
            }
        }
    }
    fun ensureVpnConsent(action: () -> Unit) {
        val prepare = VpnService.prepare(context)
        if (prepare == null) {
            action()
        } else {
            pendingAction = action
            consentLauncher.launch(prepare)
        }
    }

    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("加入 HzNet", fontSize = 24.sp, fontWeight = FontWeight.Bold)

        OutlinedTextField(
            value = coordAddr,
            onValueChange = { coordAddr = it },
            label = { Text("Coordination Server 地址") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = nodeName,
            onValueChange = { nodeName = it },
            label = { Text("Node Name（本机名字）") },
            modifier = Modifier.fillMaxWidth(),
        )

        Button(
            onClick = {
                ensureVpnConsent {
                    HzNetVpnService.pendingBrowserLogin = coordAddr
                    HzNetVpnService.start(context, configFor(context, coordAddr, nodeName))
                    note = "已发起浏览器登录：完成登录后回到本 App"
                    onDone()
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("浏览器登录") }

        OutlinedTextField(
            value = inviteCode,
            onValueChange = { inviteCode = it },
            label = { Text("邀请码（HZ-XXXX-XXXX）") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(
            onClick = {
                if (inviteCode.isBlank()) {
                    note = "请先输入邀请码"
                    return@OutlinedButton
                }
                ensureVpnConsent {
                    HzNetVpnService.pendingInvite = inviteCode.trim()
                    HzNetVpnService.start(context, configFor(context, coordAddr, nodeName))
                    onDone()
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("用邀请码加入") }

        note?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
    }
}

private fun configFor(context: Context, coordAddr: String, nodeName: String): String =
    EngineBridge.configJson(
        stateDir = java.io.File(context.filesDir, "hznet").path,
        coordAddr = coordAddr,
        relayAddr = null,
        relayCaPem = null,
        stunAddrs = null,
        dnsSuffix = null,
        nodeName = nodeName.takeIf { it.isNotBlank() },
    )
