package dev.hznet.android

import dev.hznet.android.engine.PhysicalDns
import dev.hznet.android.engine.PhysicalDns.Candidate
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Test

/** 推给引擎的物理网络 DNS 上游：顺序贴近默认网络，编码为 JSON 字符串数组。 */
class PhysicalDnsTest {

    private val cellular = Candidate(unmetered = false, validated = true, servers = listOf("221.11.1.67", "221.11.1.68"))
    private val wifi = Candidate(unmetered = true, validated = true, servers = listOf("192.168.28.1"))

    @Test
    fun validatedWifiComesBeforeCellular() {
        assertEquals(
            listOf("192.168.28.1", "221.11.1.67", "221.11.1.68"),
            PhysicalDns.order(listOf(cellular, wifi)),
        )
    }

    @Test
    fun unvalidatedNetworkGoesLast() {
        val captivePortal = wifi.copy(validated = false, servers = listOf("10.0.0.1"))
        assertEquals(
            listOf("221.11.1.67", "221.11.1.68", "10.0.0.1"),
            PhysicalDns.order(listOf(captivePortal, cellular)),
        )
    }

    @Test
    fun duplicatesAreDropped() {
        assertEquals(listOf("192.168.28.1"), PhysicalDns.order(listOf(wifi, wifi.copy(unmetered = false))))
    }

    @Test
    fun encodesAsJsonStringArray() {
        val json = PhysicalDns.toJson(listOf("192.168.28.1", "2001:db8::1"))
        val parsed = JSONArray(json)
        assertEquals(2, parsed.length())
        assertEquals("192.168.28.1", parsed.getString(0))
        assertEquals("2001:db8::1", parsed.getString(1))
    }
}
