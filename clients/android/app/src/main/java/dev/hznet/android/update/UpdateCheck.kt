package dev.hznet.android.update

import org.json.JSONObject
import java.security.MessageDigest

/**
 * App 内更新（规格 §9）：每天拉一次 `/dl/manifest.json`，`version` 高于自身
 * versionName 时通知；确认后下载到 cache、校验 sha256（失败丢弃并提示）、
 * 交系统安装器。纯逻辑在此（host 单测：版本比较与 sha256 校验，#102），
 * 下载与安装器交互在 [UpdateInstaller]。
 */
object UpdateCheck {

    data class FileEntry(val path: String, val sha256: String, val size: Long)

    data class Manifest(val version: String, val files: Map<String, FileEntry>)

    /** manifest.json 的解析（files 形如 {"android-arm64/hznet.apk":{sha256,size}}）。 */
    fun parseManifest(json: String): Manifest? = runCatching {
        val root = JSONObject(json)
        val files = mutableMapOf<String, FileEntry>()
        val entries = root.optJSONObject("files") ?: return@runCatching null
        val keys = entries.keys()
        while (keys.hasNext()) {
            val path = keys.next()
            val entry = entries.optJSONObject(path) ?: continue
            files[path] = FileEntry(
                path = path,
                sha256 = entry.optString("sha256"),
                size = entry.optLong("size", 0),
            )
        }
        Manifest(version = root.optString("version"), files = files)
    }.getOrNull()

    /** 语义化版本比较：candidate 严格高于 current 时 true（补丁级差也提示）。 */
    fun isNewer(current: String, candidate: String): Boolean {
        val parse: (String) -> List<Int> = { version ->
            version.split('.').map { part ->
                part.takeWhile(Char::isDigit).toIntOrNull() ?: 0
            }
        }
        val a = parse(current)
        val b = parse(candidate)
        for (i in 0 until maxOf(a.size, b.size)) {
            val left = a.getOrElse(i) { 0 }
            val right = b.getOrElse(i) { 0 }
            if (right != left) return right > left
        }
        return false
    }

    /** APK 的 manifest 条目（android-arm64/hznet.apk）。 */
    fun apkEntry(manifest: Manifest): FileEntry? =
        manifest.files["android-arm64/hznet.apk"]

    /** 下载体校验：sha256（小写 hex）一致才安装；失败即丢弃。 */
    fun sha256Matches(bytes: ByteArray, expectedHex: String): Boolean {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val actual = digest.joinToString("") { "%02x".format(it) }
        return actual.equals(expectedHex.lowercase(), ignoreCase = true)
    }

    /** APK 的下载相对路径（拼在 coord 基地址后的 /dl/ 段）。 */
    const val APK_PATH = "android-arm64/hznet.apk"
}
