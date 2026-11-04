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
 *
 * 注意：addAddress/addRoute 的地址参数必须是**纯 IP**（不带 /前缀），
 * 前缀长度单独传——引擎给的 `v4_cidr` / `ula_prefix` 是 CIDR 字符串，
 * 这里拆开。任何失败都返回 -1（绝不向 JNI 抛异常，那会把进程带崩）。
 */
class HzNetPlatform(private val service: VpnService) {

    /** Rust 调用；签名固定（JNI 注册名 establish/(Ljava/lang/String;)I）。 */
    fun establish(tunSpecJson: String): Int = try {
        val spec = JSONObject(tunSpecJson)
        val builder = service.Builder()
            .setSession("HzNet")
            .setMtu(spec.getInt("mtu"))
            .addAddress(spec.getString("ipv4"), 32)
            .addAddress(spec.getString("ipv6"), 128)
        addRouteCidr(builder, spec.getString("v4_cidr"))
        addRouteCidr(builder, spec.getString("ula_prefix"))
        builder
            .addDnsServer(spec.getString("dns_v4"))
            // 跟随物理网络（规格 §5.1）：null = 系统按默认网络判定计费/可用性。
            .setUnderlyingNetworks(null)
        val tun: ParcelFileDescriptor = builder.establish() ?: return -1
        // 所有权移交 Rust（FdTun::from_raw_fd 独占持有并在拆除时关闭）。
        tun.detachFd()
    } catch (e: Exception) {
        android.util.Log.e("hznet", "establish TUN 失败", e)
        -1
    }

    /** Rust 调用；让外层 socket 绕开本 HzNet 的 TUN。 */
    fun protect(fd: Int): Boolean = try {
        service.protect(fd)
    } catch (e: Exception) {
        android.util.Log.e("hznet", "protect socket 失败", e)
        false
    }

    /** `addr/prefix` → addRoute(addr, prefix)；格式异常时跳过该路由并记日志。 */
    private fun addRouteCidr(builder: VpnService.Builder, cidr: String) {
        val address = cidr.substringBefore('/').trim()
        val prefix = cidr.substringAfter('/', "").trim().toIntOrNull()
        if (address.isEmpty() || prefix == null) {
            android.util.Log.w("hznet", "忽略无法解析的路由前缀：$cidr")
            return
        }
        builder.addRoute(address, prefix)
    }
}
