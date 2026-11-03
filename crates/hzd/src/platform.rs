//! 桌面 `Platform` 实现（ADR-0013）：Linux hz0 / macOS utun、SO_BINDTODEVICE /
//! IP_BOUND_IF、netlink / 轮询出口监视、系统 DNS。路由守护（#24）与系统
//! DNS 接入在 establish 时一并挂上——与规格 §3.2「一次性提交地址 / 路由 /
//! DNS / MTU」对齐。

use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use hz_core::netwatch::NetEvent;
use hz_core::tun::{Tun, TunConfig, TunIo};
use hz_engine::{Platform, TunSpec};

use crate::dns;

/// 桌面平台：一个进程一份。事件源在构造时起好（Linux netlink 侦测 /
/// macOS 出口轮询），`net_events` 每次调用派生一个独立接收端（网络恢复
/// 序列、路由守护各自消费）。
pub struct DesktopPlatform {
    net_tx: tokio::sync::broadcast::Sender<NetEvent>,
    resolvconf_fallback: bool,
}

impl DesktopPlatform {
    pub fn new(resolvconf_fallback: bool) -> Self {
        let (net_tx, _) = tokio::sync::broadcast::channel(64);
        #[cfg(target_os = "linux")]
        {
            let tx = net_tx.clone();
            tokio::spawn(async move {
                let mut events = hz_core::netwatch::spawn();
                while let Some(event) = events.recv().await {
                    let _ = tx.send(event);
                }
            });
        }
        #[cfg(target_os = "macos")]
        {
            let tx = net_tx.clone();
            tokio::spawn(async move {
                let mut events = hz_core::netwatch_mac::spawn_watcher();
                while let Some(event) = events.recv().await {
                    tracing::info!(?event, "physical egress changed (macos watcher)");
                    let _ = tx.send(NetEvent::EgressChanged);
                }
            });
        }
        Self {
            net_tx,
            resolvconf_fallback,
        }
    }
}

impl Platform for DesktopPlatform {
    /// 创建 hz0 / utun 并接管路由（需 root）→ 挂 DNS 辅助地址与系统接入 →
    /// 起路由守护。失败（无 root 等）原样透出，引擎降级为纯控制面。
    fn establish(&self, spec: TunSpec) -> Result<Arc<dyn TunIo>> {
        let cfg = TunConfig {
            ipv4: spec.ipv4,
            ipv6: spec.ipv6,
            v4_cidr: spec.v4_cidr,
        };
        let tun = Tun::setup(&cfg)?;
        let device = tun.device();
        let guard = spawn_route_guard(Arc::new(tun), self.net_events());
        // DNS 辅助地址挂 hz0：应答器绑 (dns_v4, 53) 的前提；失败只告警
        // （应答器随后绑定失败也会告警，控制面照常）。
        if let Err(error) = hz_core::tun::add_secondary_addr(&spec.dns_v4) {
            tracing::warn!(%error, "add dns secondary addr failed");
        }
        dns::integrate(spec.dns_v4, self.resolvconf_fallback);
        Ok(Arc::new(DesktopTun {
            device,
            guard: Some(guard),
        }))
    }

    /// 外层 socket 绑物理出口网卡（Linux SO_BINDTODEVICE、macOS IP_BOUND_IF）：
    /// 与第三方 TUN 类网络工具共存的既有行为，经引擎的 protect 钩子统一生效。
    fn protect(&self, fd: RawFd) -> bool {
        // SAFETY：调用链上 fd 属于刚创建、尚未移交的 socket，此处同步借用。
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        hz_core::netif::bind_to_physical_egress(&borrowed).is_some()
    }

    fn net_events(&self) -> mpsc::Receiver<NetEvent> {
        let (tx, rx) = mpsc::channel(64);
        let mut sub = self.net_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
        });
        rx
    }

    fn system_dns(&self) -> Vec<IpAddr> {
        hz_core::outer_dns::system_nameservers()
    }
}

/// 桌面 TUN 读写端：包 tun crate 的 AsyncDevice；随句柄释放拆除路由守护
/// （Tun 的 Drop 拆接口，对应数据面 down / 引擎重建）。
struct DesktopTun {
    device: Arc<tun::AsyncDevice>,
    guard: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for DesktopTun {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            guard.abort();
        }
    }
}

impl TunIo for DesktopTun {
    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
        self.device.send_packet(packet)
    }

    fn recv_packet<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
    {
        self.device.recv_packet(buf)
    }
}

/// 运行中路由自检的周期（#24：被删除/被占用的 HzNet 路由 10 秒内恢复）。
const ROUTE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

/// 周期（及平台网络事件）检查 HzNet 路由，被删除或被其他网卡的同前缀
/// 路由占用时重新安装（#24）。修复记录经 `note_route_repair` 供
/// `hz status` 汇报（#25）。
/// 路由正常时只读不写、不打日志；自检本身出错只在错误变化时告警一次。
fn spawn_route_guard(
    tun: Arc<Tun>,
    mut events: mpsc::Receiver<NetEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ROUTE_CHECK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // 跳过立即的首跳：establish 刚装好路由
        let mut last_error: Option<String> = None;
        loop {
            // 周期检查；平台网络事件（网络变化恢复的唤醒源）时立即检查。
            tokio::select! {
                _ = tick.tick() => {}
                event = events.recv() => {
                    if event.is_none() {
                        return;
                    }
                }
            }
            let tun = tun.clone();
            let outcome = tokio::task::spawn_blocking(move || tun.check_and_repair_routes()).await;
            match outcome {
                Ok(Ok(repairs)) => {
                    last_error = None;
                    for repair in repairs {
                        match &repair.previous {
                            hz_core::tun::RouteHealth::TakenBy(iface) => tracing::warn!(
                                cidr = %repair.cidr,
                                taken_by = %iface,
                                "HzNet 路由被其他网卡（{iface}）的同前缀路由占用，已夺回"
                            ),
                            _ => {
                                tracing::warn!(cidr = %repair.cidr, "HzNet 路由被删除，已重新安装")
                            }
                        }
                        hz_engine::note_route_repair(repair.cidr, repair.previous);
                    }
                }
                Ok(Err(error)) => {
                    let text = error.to_string();
                    if last_error.as_deref() != Some(text.as_str()) {
                        tracing::warn!(error = %text, "HzNet 路由自检失败");
                        last_error = Some(text);
                    }
                }
                Err(error) => tracing::warn!(%error, "HzNet 路由自检任务异常"),
            }
        }
    })
}
