//! 端口映射（#77）：桌面专属的数据面伴随任务（ADR-0013——不进 Platform
//! trait，经 EngineHooks 的 aux_tasks 随数据面拉起、随 down abort）。
//! 申请 → 发布 PortMap 候选 → 租期过半续租；物理出口变化时立即重新申请；
//! 任务结束（数据面 down / hzd 退出）时尽力删除映射。
//! HZD_PORTMAP=0 关闭（不发起任何映射请求）；HZD_PORTMAP_GATEWAY 显式指定
//! 网关端点（测试注入桩网关 / 网关不在默认路由上的网络），缺省每轮现查
//! 默认网关。

use std::sync::Arc;
use std::time::Duration;

use hz_core::endpoint::{DiscoveredEndpoint, EndpointKind};
use hz_core::wire::SocketEngine;
use hz_engine::{AuxCtx, Engine};

/// 数据面伴随任务入口：开关关闭时返回空（不发起任何映射请求）。
pub fn spawn_aux(
    ctx: &AuxCtx<'_>,
    enabled: bool,
    gateway: Option<String>,
) -> Vec<tokio::task::JoinHandle<()>> {
    if !enabled {
        tracing::debug!("portmap disabled by HZD_PORTMAP=0");
        return Vec::new();
    }
    vec![spawn_portmap_task(
        ctx.daemon.clone(),
        ctx.engine.clone(),
        gateway,
    )]
}

/// 端口映射的网关端点：显式配置（`ip` 或 `ip:port`，缺省端口 5351）优先，
/// 否则每轮现查默认网关（网络切换后网关可能变化）。
fn portmap_gateway_endpoint(configured: Option<&str>) -> Option<std::net::SocketAddr> {
    if let Some(raw) = configured {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        if let Ok(endpoint) = raw.parse() {
            return Some(endpoint);
        }
        let ip: std::net::IpAddr = raw.parse().ok()?;
        return Some(std::net::SocketAddr::new(
            ip,
            hz_core::portmap::GATEWAY_PORT,
        ));
    }
    hz_core::netif::default_gateway_v4().map(|gateway| {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(gateway),
            hz_core::portmap::GATEWAY_PORT,
        )
    })
}

fn spawn_portmap_task(
    daemon: Arc<Engine>,
    engine: Arc<SocketEngine>,
    gateway: Option<String>,
) -> tokio::task::JoinHandle<()> {
    let mut egress = daemon.egress_receiver();
    tokio::spawn(async move {
        let mut egress_open = true;
        // Drop 时同步发出 lifetime=0 的删除报文（PCP/NAT-PMP）。
        struct PortMapDropGuard(Option<hz_core::portmap::PortMapLease>);
        impl Drop for PortMapDropGuard {
            fn drop(&mut self) {
                let Some(lease) = &self.0 else { return };
                let Some((gateway, datagram)) = hz_core::portmap::delete_datagram(lease) else {
                    return;
                };
                let socket = std::net::UdpSocket::bind("0.0.0.0:0");
                if let Ok(socket) = socket {
                    let _ = socket.send_to(&datagram, gateway);
                    tracing::info!(
                        protocol = lease.protocol.as_str(),
                        "port mapping deleted on shutdown"
                    );
                }
            }
        }
        let mut guard = PortMapDropGuard(None);
        // 上一份租约：续租时传给申请（PCP 复用 nonce、沿用旧外端口，候选不漂移）。
        let mut lease: Option<hz_core::portmap::PortMapLease> = None;
        loop {
            let wg_port = engine.local_addr().port();
            let mut wait = Duration::from_secs(60);
            match portmap_gateway_endpoint(gateway.as_deref()) {
                Some(endpoint) if endpoint.is_ipv4() => {
                    match hz_core::portmap::request_mapping_at(
                        endpoint,
                        wg_port,
                        lease.as_ref(),
                        true,
                    )
                    .await
                    {
                        Ok(Some(hz_core::portmap::MappingOutcome::Mapped(established))) => {
                            tracing::info!(
                                protocol = established.protocol.as_str(),
                                external = %established.external,
                                lifetime_secs = established.lifetime_secs,
                                "port mapping established"
                            );
                            daemon.set_portmap_result(
                                hz_core::netcheck::PortMapNote {
                                    protocol: Some(established.protocol.as_str().to_string()),
                                    external: Some(established.external.to_string()),
                                    multi_nat: false,
                                },
                                Some(DiscoveredEndpoint {
                                    addr: established.external,
                                    kind: EndpointKind::PortMap,
                                }),
                            );
                            // 新候选尽快报给 coord（等不及 30 秒的下一轮收集）。
                            daemon.report_endpoints_now(&engine).await;
                            // 租期过半续租（下限 30 秒，防短租期自旋）。
                            wait =
                                Duration::from_secs((established.lifetime_secs as u64 / 2).max(30));
                            guard.0 = Some(established.clone());
                            lease = Some(established);
                        }
                        Ok(Some(hz_core::portmap::MappingOutcome::MultiNat {
                            protocol,
                            external,
                        })) => {
                            tracing::warn!(
                                protocol = protocol.as_str(),
                                %external,
                                "port mapping behind another NAT (multi-NAT); not reporting a candidate, consider bridging the modem"
                            );
                            daemon.set_portmap_result(
                                hz_core::netcheck::PortMapNote {
                                    protocol: Some(protocol.as_str().to_string()),
                                    external: Some(external.to_string()),
                                    multi_nat: true,
                                },
                                None,
                            );
                        }
                        Ok(None) => {
                            daemon.set_portmap_result(
                                hz_core::netcheck::PortMapNote::default(),
                                None,
                            );
                        }
                        Err(error) => {
                            // 传输层错误（socket 建立失败等）视为暂时性：保留上次的
                            // 状态与候选不清空，与 Ok(None)（确定无网关应答）不同。
                            tracing::debug!(%error, "portmap request failed");
                        }
                    }
                }
                None => {
                    tracing::debug!("no default gateway; port mapping not attempted");
                }
                // IPv6 网关：端口映射协议只走 IPv4，本轮跳过。
                Some(_) => {
                    tracing::debug!("portmap gateway must be IPv4");
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                changed = egress.changed(), if egress_open => {
                    egress_open = changed.is_ok();
                    tracing::info!("egress changed, re-requesting port mapping");
                }
            }
        }
    })
}
