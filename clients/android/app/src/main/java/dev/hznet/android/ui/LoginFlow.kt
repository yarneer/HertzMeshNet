package dev.hznet.android.ui

import dev.hznet.android.backend.HzBackend
import dev.hznet.android.backend.call
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * 浏览器登录引导流（规格 §8）：
 * 1. `up`（无凭据）→ 引擎返回 login_url；
 * 2. UI 用 Custom Tabs 打开 login_url；
 * 3. 每 2 秒轮询 `login_poll` 至终态（10 分钟预算，与引擎侧一致）；
 * 4. 完成后回调（UI 把 App 切回前台）。
 *
 * 视图模型只依赖 [HzBackend]——单测注入假实现与手动调度器覆盖轮询终态。
 */
class LoginFlow(
    private val backend: HzBackend,
    private val onStarted: (loginUrl: String) -> Unit,
    private val onFinished: (outcome: Outcome) -> Unit,
    private val scheduler: PollScheduler = PollScheduler.everyTwoSeconds(),
) {
    enum class Outcome { COMPLETED, FAILED, TIMED_OUT }

    /** 轮询调度器：注册周期任务，返回取消句柄（测试用手动实现）。 */
    fun interface PollScheduler {
        fun schedule(task: () -> Unit): () -> Unit

        companion object {
            fun everyTwoSeconds(): PollScheduler {
                val executor = Executors.newSingleThreadScheduledExecutor { thread ->
                    thread.isDaemon = true
                    thread
                }
                return PollScheduler { task ->
                    val future = executor.scheduleWithFixedDelay(
                        task, 2, 2, TimeUnit.SECONDS
                    )
                    { future.cancel(false) }
                }
            }
        }
    }

    private var cancelPolling: (() -> Unit)? = null
    private var pollCount = 0
    private var finished = false

    /** 发起登录；结果经构造时的回调透出。 */
    fun begin(coordAddr: String) {
        val up = backend.call("up", JSONObject().put("coord_addr", coordAddr))
        val result = up.getOrNull() ?: run {
            finish(Outcome.FAILED)
            return
        }
        val loginUrl = result.optString("login_url")
        if (loginUrl.isBlank()) {
            // 已注册的幂等 up 直接返回身份：视为完成。
            finish(if (result.has("node_id")) Outcome.COMPLETED else Outcome.FAILED)
            return
        }
        onStarted(loginUrl)
        cancelPolling = scheduler { pollOnce() }
    }

    private fun pollOnce() {
        if (finished) return
        pollCount += 1
        // 引擎侧登录等待 10 分钟；这里同步预算后停止。
        if (pollCount > 300) {
            finish(Outcome.TIMED_OUT)
            return
        }
        val reply = backend.call("login_poll").getOrNull() ?: return
        when (reply.optString("state")) {
            "completed" -> finish(Outcome.COMPLETED)
            "failed" -> finish(Outcome.FAILED)
            // pending：继续轮询。
        }
    }

    private fun finish(outcome: Outcome) {
        if (finished) return
        finished = true
        cancelPolling?.invoke()
        cancelPolling = null
        onFinished(outcome)
    }

    fun cancel() {
        finish(Outcome.FAILED)
    }
}
