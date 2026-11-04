package dev.hznet.android.engine

import org.json.JSONArray

/**
 * 推给引擎的物理网络 DNS 上游（`onNetworkChanged`，DNS 转发模式的 system_dns）。
 *
 * - 只取非 VPN 网络：VPN 网络自己的 DNS 是 `dns_v4`，转发给它等于转发给自己。
 * - 引擎按列表顺序依次尝试，而 protect 过的转发 socket 走系统默认物理网络，
 *   所以顺序要贴近默认网络：已验证的 Wi-Fi / 以太网在前，蜂窝在后（与系统
 *   选默认网络的偏好一致；运营商 DNS 常拒绝来自别家网络的查询）。
 * - 编码为 JSON 字符串数组（Rust 端按 `Vec<String>` 解析；`List.toString()`
 *   不带引号，解析必败）。
 */
object PhysicalDns {

    data class Candidate(
        val unmetered: Boolean,
        val validated: Boolean,
        val servers: List<String>,
    )

    fun order(candidates: Collection<Candidate>): List<String> =
        candidates
            .sortedWith(
                compareByDescending<Candidate> { it.validated }
                    .thenByDescending { it.unmetered },
            )
            .flatMap { it.servers }
            .distinct()

    fun toJson(servers: List<String>): String = JSONArray(servers).toString()
}
