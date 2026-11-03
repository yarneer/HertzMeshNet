//! 平台能力接缝（ADR-0013）：引擎编排与系统调用解耦的点。
//! Linux / macOS 的实现在 hzd（包现有 tun/utun、netlink/轮询、系统 DNS）；
//! Android 的实现在 hz-android（VpnService TUN fd、protect 回调、Kotlin
//! ConnectivityManager 推送）。引擎内只依赖本 trait。

use std::net::IpAddr;
use std::os::fd::RawFd;

use anyhow::Result;
use tokio::sync::mpsc;

use hz_core::netwatch::NetEvent;
use hz_core::tun::TunIo;

/// 提交给平台的一次性 TUN 规格：地址、路由段、DNS 应答地址与 MTU。
/// Android 只把 `v4_cidr` 与本 HzNet 的 ULA 前缀路由进隧道（规格 §5.1）；
/// 桌面据此创建 hz0 / utun 并接管路由。
#[derive(Debug, Clone)]
pub struct TunSpec {
    /// 本机 Node Address（v4）。
    pub ipv4: std::net::Ipv4Addr,
    /// 本机 Node Address（v6，ULA）。
    pub ipv6: std::net::Ipv6Addr,
    /// HzNet IPv4 段（CIDR，如 `100.96.0.0/16`）。
    pub v4_cidr: String,
    /// 段内 DNS 应答地址（TUN 声明的 DNS 服务器）。
    pub dns_v4: std::net::Ipv4Addr,
    /// TUN MTU（桌面沿用 hz-core 常量；Android 传给 VpnService.Builder）。
    pub mtu: u16,
}

/// 平台能力（规格 §3.2）。四个方法覆盖引擎需要的全部系统副作用；
/// 路由守护、冲突检测、Port Map 等桌面专属职责不进本 trait。
pub trait Platform: Send + Sync {
    /// 一次性提交地址、路由、DNS、MTU，返回 TUN 读写端。重复调用（网络
    /// 切换、`up` 恢复）以新设备替换旧设备——旧端随引用释放拆除。
    fn establish(&self, spec: TunSpec) -> Result<std::sync::Arc<dyn TunIo>>;

    /// 让外层 socket 不进入本 HzNet 的 TUN（桌面绑物理出口网卡，Android
    /// 调 VpnService.protect）。返回是否成功。
    fn protect(&self, fd: RawFd) -> bool;

    /// 物理网络变化事件流（Linux netlink、macOS 轮询、Android Kotlin 推送）。
    /// 引擎的网络恢复序列消费它；桌面实现同时供路由守护复用。
    fn net_events(&self) -> mpsc::Receiver<NetEvent>;

    /// 物理网络当前的 DNS 服务器（引擎 DNS 转发模式的上游，#98）。
    fn system_dns(&self) -> Vec<IpAddr>;
}
