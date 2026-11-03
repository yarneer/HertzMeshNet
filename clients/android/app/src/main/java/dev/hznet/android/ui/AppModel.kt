package dev.hznet.android.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.json.JSONObject

/**
 * App 的可观察状态（UI 的唯一数据源是 `subscribe` 快照，规格 §8）。
 * #99 只承载最小状态；#100 在此之上落七态判定与完整界面。
 */
object AppModel {
    /** 最近一份订阅快照（status 全量，含 desired_state）。 */
    var snapshot: JSONObject? by mutableStateOf(null)
        private set

    /** 最近一次被其他 VPN 接管的时刻（onRevoke；七态判定输入）。 */
    var revokedAtMillis: Long? by mutableStateOf(null)
        private set

    /** 引擎是否在运行（start/stop 状态；UI 开关的即时反馈）。 */
    var engineRunning: Boolean by mutableStateOf(false)

    /** 运行中到达的 hznet://join 深链（onNewIntent → UI 确认框）。 */
    var pendingDeepLink: String? by mutableStateOf(null)
        private set

    fun publish(snapshot: JSONObject) {
        this.snapshot = snapshot
    }

    fun noteRevoked() {
        revokedAtMillis = System.currentTimeMillis()
    }

    fun offerDeepLink(link: String) {
        pendingDeepLink = link
    }

    fun consumeDeepLink() {
        pendingDeepLink = null
    }
}
