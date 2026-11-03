package dev.hznet.android.engine

import org.json.JSONObject

/**
 * JNI 桥（规格 §6）：Rust 侧导出函数的 Kotlin 声明。跨语言契约为 JSON
 * 字符串；`clients/fixtures/` 是解码契约的测试基准（App 单测逐个解码）。
 *
 * 生命周期：VpnService 进程内一个引擎。`start` 幂等（已运行时直接成功），
 * `stop` 拆运行时与数据面。
 */
object EngineBridge {
    init {
        System.loadLibrary("hz_android")
    }

    /** 引擎配置（start 的 configJson；Android 档位由 Rust 侧补齐）。 */
    fun configJson(
        stateDir: String,
        coordAddr: String?,
        relayAddr: String?,
        relayCaPem: String?,
        stunAddrs: List<String>?,
        dnsSuffix: String?,
        nodeName: String? = null,
    ): String = JSONObject().apply {
        put("state_dir", stateDir)
        putOpt("coord_addr", coordAddr?.takeIf { it.isNotBlank() })
        putOpt("relay_addr", relayAddr?.takeIf { it.isNotBlank() })
        putOpt("relay_ca_pem", relayCaPem?.takeIf { it.isNotBlank() })
        stunAddrs?.takeIf { it.isNotEmpty() }?.let { put("stun_addrs", it) }
        putOpt("dns_suffix", dnsSuffix?.takeIf { it.isNotBlank() })
        putOpt("node_name", nodeName?.takeIf { it.isNotBlank() })
    }.toString()

    /** 平台回调（establish / protect）与引擎启动；成功返回 true。 */
    external fun start(configJson: String, platform: Any): Boolean

    /** 成员档请求：`{"method":…,"params":…}` → `{"ok":true,"result":…}`。 */
    external fun request(requestJson: String): String

    /** 订阅快照（与 IPC subscribe 同形状的 Response JSON 行，含 desired_state）。 */
    external fun subscribe(callback: SnapshotSink)

    /** 停数据面与运行时；幂等。 */
    external fun stop()

    /** 物理网络变化：当前 DNS 服务器（JSON 字符串数组）驱动恢复与转发上游。 */
    external fun onNetworkChanged(dnsServersJson: String)

    /** 当前 Desired State（"up" / "down"）。 */
    external fun desiredState(): String

    /** 环形日志快照（脱敏后，JSON 字符串数组）。 */
    external fun ringLogTail(): String
}

/** 订阅回调：每份快照一行 JSON（Response::Ok 形状）。 */
fun interface SnapshotSink {
    fun onSnapshot(snapshotJson: String)
}
