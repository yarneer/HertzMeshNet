package dev.hznet.android.engine

import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONObject

/**
 * Rust `Platform` 的 Android 实现（规格 §6 Rust → Kotlin 回调）：
 * - `establish(tunSpecJson)`：VpnService.Builder 建立 TUN——只路由
 *   `v4_cidr` 与本 HzNet 的 ULA 前缀（规格 §5.1，其余流量走物理网络），
 *   DNS 为 `dns_v4`，MTU 按引擎给定；返回 detach 后的 fd。
 * - `protect(fd)`：VpnService.protect——外层 socket 不进本 HzNet 的 TUN。
 */
class HzNetPlatform(private val service: VpnService) {

    /** Rust 调用；签名固定（JNI 注册名 establish/(Ljava/lang/String;)I）。 */
    fun establish(tunSpecJson: String): Int {
        val spec = JSONObject(tunSpecJson)
        val builder = service.Builder()
            .setSession("HzNet")
            .setMtu(spec.getInt("mtu"))
            .addAddress(spec.getString("ipv4"), 32)
            .addAddress(spec.getString("ipv6"), 128)
            .addRoute(spec.getString("v4_cidr"), cidrPrefix(spec.getString("v4_cidr")))
            .addRoute(spec.getString("ula_prefix"), 48)
            .addDnsServer(spec.getString("dns_v4"))
            // 跟随物理网络（规格 §5.1）：null = 系统按默认网络判定计费/可用性。
            .setUnderlyingNetworks(null)
        val tun: ParcelFileDescriptor = builder.establish()
            ?: return -1
        // 所有权移交 Rust（FdTun::from_raw_fd 独占持有并在拆除时关闭）。
        return tun.detachFd()
    }

    /** Rust 调用；让外层 socket 绕开本 HzNet 的 TUN。 */
    fun protect(fd: Int): Boolean = service.protect(fd)

    private fun cidrPrefix(cidr: String): Int = cidr.substringAfter('/').toInt()
}
