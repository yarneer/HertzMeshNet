package dev.hznet.android.ui

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface

/**
 * 单 Activity（规格 §8）：完整界面（#100）由 `subscribe` 快照驱动；深链
 * `hznet://join` 经 intent 进入（校验与确认在 HzNetApp 内）。
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val deepLink = intent?.takeIf {
            it.action == Intent.ACTION_VIEW && it.data?.scheme == "hznet"
        }?.data?.toString()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    HzNetApp(deepLinkInput = deepLink)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // singleTask：深链在运行中到达时经 AppModel 交给 UI。
        intent.data?.toString()?.takeIf { it.startsWith("hznet://") }?.let {
            AppModel.offerDeepLink(it)
        }
    }
}
