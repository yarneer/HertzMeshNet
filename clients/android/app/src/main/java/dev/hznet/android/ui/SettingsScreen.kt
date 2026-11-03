package dev.hznet.android.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.hznet.android.engine.EngineBridge

/**
 * 设置页（规格 §8）：coord 地址只读展示、版本、检查更新入口（完整更新流
 * 在 #102）、电池优化白名单提示与跳转（后台常断开时的自救，规格 §7）。
 */
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val snapshot = AppModel.snapshot

    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("设置", fontSize = 24.sp, fontWeight = FontWeight.Bold)

        SettingRow("Coordination Server", snapshot?.optString("coord_addr")?.takeIf { it.isNotBlank() } ?: "未注册")
        SettingRow(
            "Node",
            snapshot?.let { "${it.optString("name")} · ${it.optString("ipv4")}" } ?: "—",
        )
        SettingRow("App 版本", appVersion(context))
        SettingRow("引擎版本", snapshot?.optString("version")?.takeIf { it.isNotBlank() } ?: "—")

        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("返回") }

        var updateNote by remember { mutableStateOf<String?>(null) }
        Button(
            onClick = {
                updateNote = "正在检查…"
                Thread {
                    val error = dev.hznet.android.update.Updater.downloadAndInstall(
                        context, appVersion(context),
                    )
                    updateNote = error ?: "已交给系统安装器（升级保留 Node 身份）"
                }.start()
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("检查更新") }

        updateNote?.let {
            Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        OutlinedButton(
            onClick = {
                // 电池优化白名单跳转（诊断提示，规格 §7：不主动申请，仅提示）。
                runCatching {
                    context.startActivity(
                        Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                            .setData(Uri.parse("package:${context.packageName}"))
                    )
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("电池优化白名单（后台常断开时）") }

    }
}

@Composable
private fun SettingRow(label: String, value: String) {
    Column {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Bold)
    }
}

private fun appVersion(context: Context): String =
    runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }
        .getOrNull() ?: "0.0.0"
