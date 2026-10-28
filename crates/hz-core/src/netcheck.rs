//! `hz netcheck` 的诊断报告（#65）。纯数据与判定放在这里，探测本身在 hzd：
//! 只读命令向运行中的守护进程要这份报告，再按人类可读或 `--json` 打出来。

use std::net::IpAddr;

use anyhow::Error;
use serde::{Deserialize, Serialize};

use crate::netif::RoutePicture;

/// 一次 `netcheck` 的全部结论。字段名是 `--json` 的稳定契约。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetcheckReport {
    pub egress: RoutePicture,
    pub udp: UdpReport,
    pub stun: StunReport,
    pub endpoints: Vec<EndpointNote>,
    pub ipv6_usable: bool,
    pub relay_rtt_ms: Option<f64>,
    pub peers: Vec<PeerNote>,
}

/// 分别向 Relay 的 STUN 服务做的 IPv4 / IPv6 外发探测。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpReport {
    pub ipv4: UdpProbe,
    pub ipv6: UdpProbe,
}

/// 一族 UDP 的探测结果。`stage = "send"` 表示报文没离开本机（底层 errno
/// 在 `error`，例如 `EINVAL`）；`stage = "query"` 表示发出去了但没有得到映射。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpProbe {
    pub ok: bool,
    pub stage: Option<String>,
    pub error: Option<String>,
    pub mapped: Option<String>,
}

/// STUN 映射与 NAT 形态。目标不足两个、或成功映射不足两个时 `nat` 为「无法判断」。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StunReport {
    pub targets: usize,
    pub mapped: Vec<String>,
    pub nat: String,
}

/// 上报给 Coordination Server 的一个 Endpoint。`suspicious` 为空表示看不出问题。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointNote {
    pub addr: String,
    pub kind: String,
    /// `198.18.0.0/15`、`loopback`、`virtual_nic`。
    pub suspicious: Vec<String>,
}

/// 一个对端的当前路径与最近一次打洞结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNote {
    pub name: String,
    pub node_id: String,
    /// `"direct"` / `"relay"`；数据面未拉起时为 null。
    pub path: Option<String>,
    /// `"success"` / `"attempted"` / `"fallback"` / `"skipped"`；还没打过洞为 null。
    pub punch: Option<String>,
}

/// IPv4 STUN 目标不足两个，或成功映射不足两个：不猜测。
/// 两个及以上映射端口不一致，视为端点相关（对称 NAT）。
///
/// ponytail: 只比映射端口，不是 RFC 5780 的完整分类；要更细再加 CHANGE-REQUEST。
pub fn nat_verdict(ipv4_targets: usize, mapped_ports: &[u16]) -> &'static str {
    if ipv4_targets < 2 || mapped_ports.len() < 2 {
        "无法判断"
    } else if mapped_ports.iter().all(|port| *port == mapped_ports[0]) {
        "端点无关"
    } else {
        "端点相关（对称 NAT），直连概率低"
    }
}

/// 把 STUN 查询的失败归成（阶段, 展示用错误）。发送失败优先取 errno 名，
/// 这样 macOS 双栈缺陷会显示成 `EINVAL` 而不是 "Invalid argument"。
pub fn classify_udp_error(err: &Error) -> (&'static str, String) {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.raw_os_error().is_some() {
                return ("send", errno_label(io));
            }
        }
    }
    let text = err.to_string();
    if text.contains("超时") {
        ("query", "超时".to_string())
    } else {
        ("query", text)
    }
}

fn errno_label(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        Some(libc::EINVAL) => "EINVAL".to_string(),
        Some(libc::EACCES) => "EACCES".to_string(),
        Some(libc::EPERM) => "EPERM".to_string(),
        Some(libc::EADDRNOTAVAIL) => "EADDRNOTAVAIL".to_string(),
        Some(libc::EAFNOSUPPORT) => "EAFNOSUPPORT".to_string(),
        Some(libc::ENETUNREACH) => "ENETUNREACH".to_string(),
        Some(libc::EHOSTUNREACH) => "EHOSTUNREACH".to_string(),
        Some(libc::ENETDOWN) => "ENETDOWN".to_string(),
        Some(libc::ENODEV) => "ENODEV".to_string(),
        Some(libc::ECONNREFUSED) => "ECONNREFUSED".to_string(),
        Some(libc::EMSGSIZE) => "EMSGSIZE".to_string(),
        Some(libc::ENOBUFS) => "ENOBUFS".to_string(),
        _ => err.to_string(),
    }
}

/// 可疑原因。`on_virtual_nic` 由调用方根据地址所在网卡判定。
pub fn suspicions(ip: IpAddr, on_virtual_nic: bool) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if crate::outer_dns::is_fake_ip(&ip) {
        flags.push("198.18.0.0/15");
    }
    if ip.is_loopback() {
        flags.push("loopback");
    }
    if on_virtual_nic {
        flags.push("virtual_nic");
    }
    flags
}

/// 人类可读报告。告警句（`IPv4 UDP 外发失败：EINVAL`、LAN 假地址）是稳定文案。
pub fn format_report(report: &NetcheckReport) -> String {
    let mut lines = Vec::new();
    let physical = report.egress.physical.as_deref().unwrap_or("未知");
    let holder = match &report.egress.default_route {
        Some(iface) if report.egress.virtual_holds_default => {
            format!("{iface}（虚拟网卡持有）")
        }
        Some(iface) => iface.clone(),
        None => "未知".to_string(),
    };
    lines.push(format!("物理出口：{physical}"));
    lines.push(format!("默认路由：{holder}"));
    lines.push(udp_line("IPv4", &report.udp.ipv4));
    lines.push(udp_line("IPv6", &report.udp.ipv6));
    let mapped = if report.stun.mapped.is_empty() {
        "无".to_string()
    } else {
        report.stun.mapped.join("、")
    };
    lines.push(format!("STUN 映射：{mapped}"));
    lines.push(format!("NAT：{}", report.stun.nat));
    lines.push(format!(
        "可用 IPv6：{}",
        if report.ipv6_usable { "是" } else { "否" }
    ));
    lines.push(match report.relay_rtt_ms {
        Some(ms) => format!("到 Relay 的 RTT：{ms:.1} ms"),
        None => "到 Relay 的 RTT：未知".to_string(),
    });
    if report.endpoints.is_empty() {
        lines.push("上报的 Endpoint：无".to_string());
    } else {
        lines.push("上报的 Endpoint：".to_string());
        for endpoint in &report.endpoints {
            lines.push(endpoint_line(endpoint));
        }
    }
    if report.peers.is_empty() {
        lines.push("对端：无".to_string());
    } else {
        lines.push("对端：".to_string());
        for peer in &report.peers {
            lines.push(format!(
                "  {}  {}  最近打洞：{}",
                peer.name,
                path_label(peer.path.as_deref()),
                punch_label(peer.punch.as_deref()),
            ));
        }
    }
    lines.join("\n")
}

fn udp_line(family: &str, probe: &UdpProbe) -> String {
    if probe.ok {
        match &probe.mapped {
            Some(mapped) => format!("{family} UDP 外发成功，映射 {mapped}"),
            None => format!("{family} UDP 外发成功"),
        }
    } else if probe.stage.as_deref() == Some("send") {
        format!(
            "{family} UDP 外发失败：{}",
            probe.error.as_deref().unwrap_or("未知错误")
        )
    } else {
        format!(
            "{family} UDP 查询失败：{}",
            probe.error.as_deref().unwrap_or("未知错误")
        )
    }
}

fn endpoint_line(note: &EndpointNote) -> String {
    let fake = note.suspicious.iter().any(|flag| flag == "198.18.0.0/15");
    if note.kind == "lan" && fake {
        format!("  ⚠ LAN Endpoint {} 落在 198.18.0.0/15", note.addr)
    } else if note.suspicious.is_empty() {
        format!("  {} {}", note.kind, note.addr)
    } else {
        format!(
            "  ⚠ {} {}（{}）",
            note.kind,
            note.addr,
            note.suspicious.join("、")
        )
    }
}

fn path_label(path: Option<&str>) -> &'static str {
    match path {
        Some("direct") => "Direct Path",
        Some("relay") => "Relayed Path",
        _ => "未知",
    }
}

fn punch_label(punch: Option<&str>) -> &'static str {
    match punch {
        Some("success") => "成功",
        Some("attempted") => "已尝试",
        Some("fallback") => "退回中转",
        Some("skipped") => "跳过",
        _ => "无",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> NetcheckReport {
        NetcheckReport {
            egress: RoutePicture {
                physical: Some("eth0".to_string()),
                default_route: Some("utun4".to_string()),
                virtual_holds_default: true,
            },
            udp: UdpReport {
                ipv4: UdpProbe {
                    ok: false,
                    stage: Some("send".to_string()),
                    error: Some("EINVAL".to_string()),
                    mapped: None,
                },
                ipv6: UdpProbe {
                    ok: true,
                    stage: None,
                    error: None,
                    mapped: Some("[2001:db8::8]:51820".to_string()),
                },
            },
            stun: StunReport {
                targets: 1,
                mapped: vec!["[2001:db8::8]:51820".to_string()],
                nat: nat_verdict(1, &[51820]).to_string(),
            },
            endpoints: vec![EndpointNote {
                addr: "198.18.0.1:51820".to_string(),
                kind: "lan".to_string(),
                suspicious: suspicions("198.18.0.1".parse().unwrap(), true)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            }],
            ipv6_usable: false,
            relay_rtt_ms: None,
            peers: vec![PeerNote {
                name: "mini".to_string(),
                node_id: "n-mini".to_string(),
                path: Some("relay".to_string()),
                punch: Some("attempted".to_string()),
            }],
        }
    }

    #[test]
    fn report_json_snapshot_locks_the_field_names() {
        let pretty = serde_json::to_string_pretty(&fixture()).unwrap();
        assert_eq!(
            pretty,
            r#"{
  "egress": {
    "physical": "eth0",
    "default_route": "utun4",
    "virtual_holds_default": true
  },
  "udp": {
    "ipv4": {
      "ok": false,
      "stage": "send",
      "error": "EINVAL",
      "mapped": null
    },
    "ipv6": {
      "ok": true,
      "stage": null,
      "error": null,
      "mapped": "[2001:db8::8]:51820"
    }
  },
  "stun": {
    "targets": 1,
    "mapped": [
      "[2001:db8::8]:51820"
    ],
    "nat": "无法判断"
  },
  "endpoints": [
    {
      "addr": "198.18.0.1:51820",
      "kind": "lan",
      "suspicious": [
        "198.18.0.0/15",
        "virtual_nic"
      ]
    }
  ],
  "ipv6_usable": false,
  "relay_rtt_ms": null,
  "peers": [
    {
      "name": "mini",
      "node_id": "n-mini",
      "path": "relay",
      "punch": "attempted"
    }
  ]
}"#
        );
    }

    #[test]
    fn human_report_shows_einval_and_fake_lan_endpoint() {
        let text = format_report(&fixture());
        assert!(
            text.contains("IPv4 UDP 外发失败：EINVAL"),
            "IPv4 外发失败必须带底层错误：{text}"
        );
        assert!(
            text.contains("⚠ LAN Endpoint 198.18.0.1:51820 落在 198.18.0.0/15"),
            "198.18.0.0/15 的 LAN Endpoint 必须告警：{text}"
        );
        assert!(text.contains("默认路由：utun4（虚拟网卡持有）"), "{text}");
        assert!(text.contains("NAT：无法判断"), "{text}");
        assert!(
            text.contains("mini  Relayed Path  最近打洞：已尝试"),
            "{text}"
        );
    }

    #[test]
    fn nat_verdict_refuses_to_guess_below_two_targets() {
        assert_eq!(nat_verdict(0, &[]), "无法判断");
        assert_eq!(nat_verdict(1, &[4000]), "无法判断");
        assert_eq!(nat_verdict(2, &[4000]), "无法判断");
        assert_eq!(nat_verdict(2, &[4000, 4000]), "端点无关");
        assert!(nat_verdict(2, &[4000, 4001]).contains("直连概率低"));
    }

    #[test]
    fn send_failure_surfaces_einval_and_timeout_stays_a_query_failure() {
        let send = std::io::Error::from_raw_os_error(libc::EINVAL);
        let wrapped =
            anyhow::Error::from(send).context("stun request send to 203.0.113.1:3478 failed");
        assert_eq!(classify_udp_error(&wrapped), ("send", "EINVAL".to_string()));
        let timeout = anyhow::anyhow!("stun 查询 203.0.113.1:3478 超时（3000ms）");
        assert_eq!(classify_udp_error(&timeout), ("query", "超时".to_string()));
    }

    #[test]
    fn suspicions_flag_fake_loopback_and_virtual_nic() {
        let fake: IpAddr = "198.18.0.1".parse().unwrap();
        let edge: IpAddr = "198.19.255.255".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let lan: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(suspicions(fake, false), vec!["198.18.0.0/15"]);
        assert_eq!(suspicions(edge, true), vec!["198.18.0.0/15", "virtual_nic"]);
        assert_eq!(suspicions(loopback, false), vec!["loopback"]);
        assert!(suspicions(lan, false).is_empty());
        assert_eq!(suspicions(lan, true), vec!["virtual_nic"]);
    }
}
