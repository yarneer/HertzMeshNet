package dev.hznet.android.diagnostics

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 诊断包（规格 §8）：`diagnostics`（引擎，log_tail 已脱敏）+ App 版本、
 * Android 版本、机型、私人 DNS 模式、电池白名单状态，打包为
 * `hznet-diagnostics-<node>-<时间>.zip`，经系统分享面板发出。
 *
 * 纯 JVM 实现（java.util.zip + org.json）——host 单测覆盖打包结构与
 * 二次脱敏（#101：注入私钥 / Auth Key / 邀请码 / 登录 token 的日志行
 * 必须被去除）。
 */
object DiagnosticsExport {

    /** 引擎脱敏规则的 Kotlin 镜像（防御纵深：引擎已脱敏，这里再过一遍）。 */
    fun redactLine(line: String): String {
        if (line.contains("PRIVATE KEY")) return "…[REDACTED]（PEM 私钥块）"
        var out = redactPrefixedSecret(line, "hznet.")
        out = redactPrefixedSecret(out, "hzrelay.")
        out = redactInviteCodes(out)
        out = redactLoginTokens(out)
        return redactLongHex(out)
    }

    private fun redactPrefixedSecret(line: String, prefix: String): String {
        val regex = Regex(Regex.escape(prefix) + "[A-Za-z0-9_-]{20,}")
        return regex.replace(line) { match -> "$prefix[REDACTED](${match.value.length})" }
    }

    private fun redactInviteCodes(line: String): String =
        line.replace(Regex("HZ-[A-Z0-9]{4}-[A-Z0-9]{4}"), "HZ-[REDACTED]")

    private fun redactLoginTokens(line: String): String =
        line.replace(Regex("""/oidc/start/[A-Za-z0-9_-]+"""), "/oidc/start/[REDACTED]")

    private fun redactLongHex(line: String): String =
        line.replace(Regex("""(?i)\b[0-9a-f]{64,}\b"""), "[REDACTED]")

    data class Meta(
        val appVersion: String,
        val androidVersion: String,
        val model: String,
        val privateDnsMode: String,
        val batteryWhitelisted: Boolean,
    )

    /** 诊断 zip 的文件名（不含扩展名）：hznet-diagnostics-<node>-<毫秒时间戳>。 */
    fun fileName(nodeName: String, epochMillis: Long): String {
        val safeNode = nodeName.ifBlank { "node" }
            .lowercase()
            .replace(Regex("[^a-z0-9-]"), "-")
        return "hznet-diagnostics-$safeNode-$epochMillis"
    }

    /**
     * 组装 zip：diagnostics.json（引擎结果 + 元信息）与 diagnostics.log
     * （log_tail 逐行二次脱敏）。
     */
    fun buildZip(engineDiagnostics: JSONObject, meta: Meta): ByteArray {
        val logTail = engineDiagnostics.optJSONArray("log_tail") ?: org.json.JSONArray()
        val redacted = (0 until logTail.length()).map { redactLine(logTail.optString(it)) }

        val manifest = JSONObject().apply {
            put("app_version", meta.appVersion)
            put("android_version", meta.androidVersion)
            put("model", meta.model)
            put("private_dns_mode", meta.privateDnsMode)
            put("battery_whitelisted", meta.batteryWhitelisted)
        }
        val diagnosticsJson = JSONObject(engineDiagnostics.toString()).apply {
            // log_tail 一律是脱敏后的行（diagnostics.log 与 JSON 同源）。
            put("log_tail", org.json.JSONArray(redacted))
            put("app", manifest)
        }

        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            zip.putNextEntry(ZipEntry("diagnostics.json"))
            zip.write(diagnosticsJson.toString(2).toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("diagnostics.log"))
            zip.write(redacted.joinToString("\n").toByteArray())
            zip.closeEntry()
        }
        return out.toByteArray()
    }
}
