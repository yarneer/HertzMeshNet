package dev.hznet.android

import dev.hznet.android.backend.HzBackend
import dev.hznet.android.engine.SnapshotSink
import dev.hznet.android.ui.LoginFlow
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * #100：浏览器登录轮询（LoginFlow 只依赖 HzBackend 接口——假实现即测试
 * seam；pending → completed 的推进与终态回调、失败与无 login_url 的幂等
 * up 分支、终态后停止轮询）。
 */
class LoginFlowTest {

    /** 假后端：login_poll 按脚本顺序返回。 */
    private class FakeBackend(
        private val upResult: JSONObject,
        private val pollScript: MutableList<JSONObject>,
    ) : HzBackend {
        val requests = mutableListOf<String>()
        var pollCalls = 0
            private set

        override fun start(configJson: String, platform: Any) = true

        override fun request(method: String, params: JSONObject): JSONObject {
            requests += method
            val result = if (method == "up") {
                upResult
            } else {
                pollCalls += 1
                if (pollScript.isEmpty()) {
                    JSONObject().put("state", "pending")
                } else {
                    pollScript.removeAt(0)
                }
            }
            return JSONObject().put("ok", true).put("result", result)
        }

        override fun subscribe(sink: SnapshotSink) = Unit
        override fun stop() = Unit
        override fun desiredState() = "up"
        override fun ringLogTail() = "[]"
        override fun onNetworkChanged(dnsServers: List<String>) = Unit
    }

    /** 手动调度器：任务入队，测试逐拍触发。 */
    private class ManualScheduler : LoginFlow.PollScheduler {
        val queue = ArrayDeque<() -> Unit>()
        var cancelled = false
            private set

        override fun schedule(task: () -> Unit): () -> Unit {
            queue += task
            return {
                cancelled = true
                queue.clear()
            }
        }

        /** 触发一拍：周期任务保持登记（真实调度器会重复执行），cancel 才清空。 */
        fun runOne() = queue.firstOrNull()?.invoke() ?: error("没有排队的轮询任务")
    }

    @Test
    fun pollsUntilCompletedThenStops() {
        val backend = FakeBackend(
            JSONObject().put("login_url", "https://coord.example.com/oidc/start/abc"),
            mutableListOf(
                JSONObject().put("state", "pending"),
                JSONObject().put("state", "pending"),
                JSONObject().put("state", "completed"),
            ),
        )
        val outcomes = mutableListOf<LoginFlow.Outcome>()
        val manual = ManualScheduler()
        val flow = LoginFlow(backend, {}, { outcomes += it }, manual)

        flow.begin("https://coord.example.com")
        assertEquals(listOf<String>(), outcomes.map { it.toString() })
        manual.runOne() // pending
        manual.runOne() // pending
        manual.runOne() // completed → 终态 + 取消
        assertEquals(listOf(LoginFlow.Outcome.COMPLETED), outcomes)
        assertTrue("终态后必须取消轮询", manual.cancelled)
        assertEquals(3, backend.pollCalls)
    }

    @Test
    fun failedPollReportsFailure() {
        val backend = FakeBackend(
            JSONObject().put("login_url", "https://coord.example.com/oidc/start/xyz"),
            mutableListOf(JSONObject().put("state", "failed").put("error", "链接已过期")),
        )
        val outcomes = mutableListOf<LoginFlow.Outcome>()
        val manual = ManualScheduler()
        LoginFlow(backend, {}, { outcomes += it }, manual).begin("https://coord.example.com")
        manual.runOne()
        assertEquals(listOf(LoginFlow.Outcome.FAILED), outcomes)
    }

    @Test
    fun alreadyRegisteredUpIsImmediatelyCompleted() {
        // 已注册的 up 幂等返回身份（无 login_url）：直接完成、不轮询。
        val backend = FakeBackend(
            JSONObject().put("node_id", "n-1"),
            mutableListOf(),
        )
        val outcomes = mutableListOf<LoginFlow.Outcome>()
        LoginFlow(backend, {}, { outcomes += it }, ManualScheduler())
            .begin("https://coord.example.com")
        assertEquals(listOf(LoginFlow.Outcome.COMPLETED), outcomes)
        assertEquals(listOf("up"), backend.requests)
    }
}
