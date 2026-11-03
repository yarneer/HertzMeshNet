package dev.hznet.android.ui

import java.net.URI

/**
 * `hznet://join?coord=<https URL>&invite=<code>` 深链校验（规格 §8，规则与
 * macOS Client App 相同）。纯 JVM（java.net.URI）——host 单测无需 Android
 * 运行时。确认框由 UI 层弹（一律醒目显示 coord 域名），确认后按邀请码
 * 路径 `up`。
 *
 * - 只接受 `https://` 的 coord；其他 scheme 一律拒绝。
 * - 已注册到不同 coord 时拒绝并提示改用 CLI（切换服务器 = 换身份，App
 *   不承担该操作）。
 */
object DeepLink {

    sealed interface JoinLink {
        /** 可用：待用户确认（确认框醒目显示 coord 域名）。 */
        data class NeedsConfirmation(
            val coordUrl: String,
            /** 醒目展示的域名（确认框主文案）。 */
            val coordDomain: String,
            val inviteCode: String?,
        ) : JoinLink

        /** 拒绝：原因直接展示给用户。 */
        data class Rejected(val reason: Reason) : JoinLink
    }

    enum class Reason(val message: String) {
        NOT_JOIN_HOST("只支持 hznet://join 链接"),
        MISSING_COORD("链接缺少 coord 地址"),
        NOT_HTTPS("coord 地址必须是 https://"),
        MALFORMED_COORD("coord 地址无效"),
        DIFFERENT_COORD("本机已注册到其他 Coordination Server，切换服务器请用 hz CLI"),
    }

    /**
     * @param registeredCoord 当前注册的 coord 地址（快照 coord_addr）；
     *        null / 空串 = 未注册。
     */
    fun parse(link: String?, registeredCoord: String?): JoinLink {
        val uri = runCatching { URI(link ?: return JoinLink.Rejected(Reason.NOT_JOIN_HOST)) }
            .getOrNull() ?: return JoinLink.Rejected(Reason.NOT_JOIN_HOST)
        if (!uri.host.equals("join", ignoreCase = true)) {
            return JoinLink.Rejected(Reason.NOT_JOIN_HOST)
        }
        val params = queryParams(uri.rawQuery)
        val coord = params["coord"] ?: return JoinLink.Rejected(Reason.MISSING_COORD)
        if (!coord.startsWith("https://")) return JoinLink.Rejected(Reason.NOT_HTTPS)
        val parsed = runCatching { URI(coord) }.getOrNull()
            ?: return JoinLink.Rejected(Reason.MALFORMED_COORD)
        val domain = parsed.host?.lowercase()?.takeIf { it.isNotBlank() }
            ?: return JoinLink.Rejected(Reason.MALFORMED_COORD)
        // 已注册到不同 coord：拒绝（scheme + host + 有效端口任一不同即不同）。
        if (!registeredCoord.isNullOrBlank() && !sameServer(registeredCoord, coord)) {
            return JoinLink.Rejected(Reason.DIFFERENT_COORD)
        }
        return JoinLink.NeedsConfirmation(
            coordUrl = coord,
            coordDomain = domain,
            inviteCode = params["invite"]?.takeIf { it.isNotBlank() },
        )
    }

    /** 手工拆 query（percent-decode 只处理 %XX 与 '+'，够 join 链接用）。 */
    private fun queryParams(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        return raw.split('&').mapNotNull { pair ->
            val idx = pair.indexOf('=')
            if (idx <= 0) return@mapNotNull null
            val key = decode(pair.substring(0, idx))
            val value = decode(pair.substring(idx + 1))
            key to value
        }.toMap()
    }

    private fun decode(text: String): String = runCatching {
        java.net.URLDecoder.decode(text, Charsets.UTF_8)
    }.getOrDefault(text)

    /** 同一服务器判定：scheme + host + 有效端口全一致（缺省补 443/80）。 */
    private fun sameServer(a: String, b: String): Boolean {
        fun normalize(url: String): String? {
            val uri = runCatching { URI(url) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase() ?: return null
            val host = uri.host?.lowercase() ?: return null
            val port = if (uri.port == -1) {
                if (scheme == "https") 443 else 80
            } else {
                uri.port
            }
            return "$scheme://$host:$port"
        }
        return normalize(a) != null && normalize(a) == normalize(b)
    }
}
