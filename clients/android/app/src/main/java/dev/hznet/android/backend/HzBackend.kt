package dev.hznet.android.backend

import dev.hznet.android.engine.EngineBridge
import dev.hznet.android.engine.SnapshotSink
import org.json.JSONObject

/**
 * 后端接缝（规格 §8）：视图模型只依赖本接口，唯一实现是 JNI 桥——
 * Kotlin 侧的测试 seam（单测注入假实现）。
 */
interface HzBackend {
    /** 引擎启动（配置见 EngineBridge.configJson）。 */
    fun start(configJson: String, platform: Any): Boolean

    /** 成员档请求：返回 {"ok":bool,"result"|"error":…}。 */
    fun request(method: String, params: JSONObject = JSONObject()): JSONObject

    /** 订阅快照（每份一行 Response JSON；见 SnapshotSink）。 */
    fun subscribe(sink: SnapshotSink)

    fun stop()

    /** 当前 Desired State（"up"/"down"）。 */
    fun desiredState(): String

    /** 环形日志（脱敏后，JSON 数组字符串）。 */
    fun ringLogTail(): String

    /** 物理网络变化（DNS 服务器列表）。 */
    fun onNetworkChanged(dnsServers: List<String>)
}

/** 唯一实现：JNI 桥。 */
class JniBackend : HzBackend {
    override fun start(configJson: String, platform: Any): Boolean =
        EngineBridge.start(configJson, platform)

    override fun request(method: String, params: JSONObject): JSONObject =
        JSONObject(
            EngineBridge.request(
                JSONObject().put("method", method).put("params", params).toString()
            )
        )

    override fun subscribe(sink: SnapshotSink) = EngineBridge.subscribe(sink)

    override fun stop() = EngineBridge.stop()

    override fun desiredState(): String = EngineBridge.desiredState()

    override fun ringLogTail(): String = EngineBridge.ringLogTail()

    override fun onNetworkChanged(dnsServers: List<String>) =
        EngineBridge.onNetworkChanged(dnsServers.toString())
}

/** 请求结果的解包助手。 */
fun HzBackend.call(method: String, params: JSONObject = JSONObject()): Result<JSONObject> {
    val reply = request(method, params)
    return if (reply.optBoolean("ok")) {
        Result.success(reply.optJSONObject("result") ?: JSONObject())
    } else {
        Result.failure(IllegalStateException(reply.optString("error", "未知错误")))
    }
}
