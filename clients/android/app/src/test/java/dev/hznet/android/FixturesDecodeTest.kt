package dev.hznet.android

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * #99 契约测试：Kotlin 解码 `clients/fixtures/` 全部 fixture（作为 test
 * assets 打进单测；跨语言契约是 JSON 字符串，Swift / Kotlin 各自解码）。
 */
class FixturesDecodeTest {

    /**
     * fixtures 目录：CI / 本地经 gradle 系统属性注入；IDE 里退回工程相对
     * 路径（app → clients/android/app → 上两级是 clients/）。
     */
    private val fixturesDir: java.io.File = java.io.File(
        System.getProperty("hznet.fixtures.dir") ?: "../../../fixtures",
    )

    @Test
    fun allFixturesDecodeAsJsonObjects() {
        val files = fixturesDir.listFiles { f -> f.extension == "json" }
        assertTrue("fixtures 目录应有 JSON 文件（${fixturesDir.absolutePath}）", files != null && files.isNotEmpty())
        files!!.forEach { file ->
            val parsed = JSONObject(file.readText())
            assertTrue("fixture ${file.name} 应是对象", parsed.length() > 0)
        }
    }

    @Test
    fun registeredSnapshotDecodesCoreFields() {
        val snapshot = JSONObject(java.io.File(fixturesDir, "status-registered-direct.json").readText())
        assertEquals(true, snapshot.getBoolean("registered"))
        assertTrue(snapshot.getString("ipv4").startsWith("100."))
        assertEquals("up", snapshot.getString("desired_state"))
        assertTrue(snapshot.getJSONArray("peers").length() >= 1)
    }

    @Test
    fun unregisteredSnapshotIsLockedShape() {
        val snapshot = JSONObject(java.io.File(fixturesDir, "status-unregistered.json").readText())
        assertEquals(false, snapshot.getBoolean("registered"))
    }

    @Test
    fun revokedAndExpiredSnapshotsDecode() {
        JSONObject(java.io.File(fixturesDir, "status-revoked.json").readText())
        JSONObject(java.io.File(fixturesDir, "status-expired.json").readText())
        JSONObject(java.io.File(fixturesDir, "status-down.json").readText())
        JSONObject(java.io.File(fixturesDir, "status-registered-relay.json").readText())
        JSONObject(java.io.File(fixturesDir, "status-registered-conflict.json").readText())
        JSONObject(java.io.File(fixturesDir, "diagnostics.json").readText())
        JSONObject(java.io.File(fixturesDir, "login-pending.json").readText())
        JSONObject(java.io.File(fixturesDir, "login-completed.json").readText())
        JSONObject(java.io.File(fixturesDir, "login-failed.json").readText())
    }
}
