//! Policy 领域模型（FR-10）：TOML 文档、主体匹配、按 Node 视角的入站规则与
//! 目标侧入站过滤闸（A1）。解析与结构校验在这里（纯函数、无 I/O），
//! 依赖 users 表的存在性校验归 Coordination Server 侧。

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tag 引用的合法字符集与长度（pin：^[a-z0-9-]{1,32}$）。
fn valid_tag(tag: &str) -> bool {
    (1..=32).contains(&tag.len())
        && tag
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// 规则主体：User / Group / Tag。文本形态 "user:alice" 是 TOML 与协议共用的
/// 边界表示，parse 在边界做，内部不再存字符串前缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySubject {
    User(String),
    Group(String),
    Tag(String),
}

impl PolicySubject {
    /// 边界解析：未知前缀、空名、非法 Tag 语法都报可读中文原因。
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Some(name) = text.strip_prefix("user:") {
            if name.is_empty() {
                return Err(format!("主体 {text:?} 的 user 名为空"));
            }
            return Ok(PolicySubject::User(name.to_string()));
        }
        if let Some(name) = text.strip_prefix("group:") {
            if name.is_empty() {
                return Err(format!("主体 {text:?} 的 group 名为空"));
            }
            return Ok(PolicySubject::Group(name.to_string()));
        }
        if let Some(name) = text.strip_prefix("tag:") {
            if !valid_tag(name) {
                return Err(format!(
                    "主体 {text:?} 的 Tag {name:?} 不符合 ^[a-z0-9-]{{1,32}}$"
                ));
            }
            return Ok(PolicySubject::Tag(name.to_string()));
        }
        Err(format!(
            "主体 {text:?} 缺少前缀，必须是 group:… / user:… / tag:…"
        ))
    }

    /// 与 parse 互逆；服务端生成协议字段用，不落库。
    pub fn to_text(&self) -> String {
        match self {
            PolicySubject::User(name) => format!("user:{name}"),
            PolicySubject::Group(name) => format!("group:{name}"),
            PolicySubject::Tag(name) => format!("tag:{name}"),
        }
    }

    /// 主体是否命中一个 Node：Group 查成员表，User 比归属，Tag 查标签列表。
    /// Node 侧身份只有这两项（归属 User 与 Tag），不带 node_id。
    pub fn matches(
        &self,
        groups: &[PolicyGroup],
        owner_user: Option<&str>,
        tags: &[String],
    ) -> bool {
        match self {
            PolicySubject::User(name) => owner_user == Some(name.as_str()),
            PolicySubject::Tag(name) => tags.iter().any(|tag| tag == name),
            PolicySubject::Group(group_name) => groups
                .iter()
                .find(|group| &group.name == group_name)
                .is_some_and(|group| {
                    owner_user.is_some_and(|owner| group.users.iter().any(|u| u == owner))
                }),
        }
    }
}

/// Group 定义：名字 + 成员 User 名单。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGroup {
    pub name: String,
    pub users: Vec<String>,
}

/// 一条访问规则：主体 → 目标 : 端口。MVP 无端口通配，ports 至少一项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub from: PolicySubject,
    pub to: PolicySubject,
    pub ports: Vec<u16>,
}

/// 整份 Policy 文档。version 由服务端在入库时分配，客户端可带可不带。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyDoc {
    pub version: Option<i64>,
    pub groups: Vec<PolicyGroup>,
    pub rules: Vec<PolicyRule>,
}

impl PolicyDoc {
    /// 一对 Node 是否被任一规则连通（任一方向）：Network Map 可见性判据
    /// （ADR-0006：允许它访问、或允许访问它的 Node）。
    pub fn pair_connected(
        &self,
        a: (Option<&str>, &[String]),
        b: (Option<&str>, &[String]),
    ) -> bool {
        self.rules.iter().any(|rule| {
            (rule.from.matches(&self.groups, a.0, a.1) && rule.to.matches(&self.groups, b.0, b.1))
                || (rule.from.matches(&self.groups, b.0, b.1)
                    && rule.to.matches(&self.groups, a.0, a.1))
        })
    }

    /// to 侧命中 me 的规则集合：即 me 这个 Node 收到的入站过滤规则（A1）。
    pub fn inbound_rules_for(&self, me: (Option<&str>, &[String])) -> Vec<InboundRule> {
        self.rules
            .iter()
            .filter(|rule| rule.to.matches(&self.groups, me.0, me.1))
            .map(|rule| InboundRule {
                from: rule.from.clone(),
                ports: rule.ports.clone(),
            })
            .collect()
    }
}

/// 下发给单个 Node 的入站规则：from 主体 + 允许端口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRule {
    pub from: PolicySubject,
    pub ports: Vec<u16>,
}

/// TOML 原文的结构形态。deny_unknown_fields：拼错字段名必须报错而不是被忽略。
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    version: Option<i64>,
    #[serde(default)]
    group: Vec<RawGroup>,
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    name: String,
    #[serde(default)]
    users: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    from: String,
    to: String,
    ports: Vec<i64>,
}

/// 解析并做结构校验（不查 users 表）：TOML 语法、主体语法、Group 唯一且被
/// 引用即定义、端口 1..=65535 且非空。空规则列表合法（等于全拒绝）。
pub fn parse_policy(content: &str) -> Result<PolicyDoc, String> {
    let raw: RawPolicy = toml::from_str(content).map_err(|e| format!("TOML 解析失败：{e}"))?;
    let mut doc = PolicyDoc {
        version: raw.version,
        groups: Vec::with_capacity(raw.group.len()),
        rules: Vec::with_capacity(raw.rule.len()),
    };
    for group in &raw.group {
        if group.name.is_empty() {
            return Err("存在 name 为空的 Group".to_string());
        }
        if doc.groups.iter().any(|g| g.name == group.name) {
            return Err(format!("Group 名字重复：{}", group.name));
        }
        doc.groups.push(PolicyGroup {
            name: group.name.clone(),
            users: group.users.clone(),
        });
    }
    for (index, rule) in raw.rule.iter().enumerate() {
        let at = format!("第 {} 条 rule", index + 1);
        let from = PolicySubject::parse(&rule.from).map_err(|e| format!("{at} 的 from {e}"))?;
        let to = PolicySubject::parse(&rule.to).map_err(|e| format!("{at} 的 to {e}"))?;
        if rule.ports.is_empty() {
            return Err(format!(
                "{at} 的 ports 为空；MVP 不支持通配端口，须逐项列出"
            ));
        }
        let mut ports = Vec::with_capacity(rule.ports.len());
        for port in &rule.ports {
            if !(1..=u16::MAX as i64).contains(port) {
                return Err(format!("{at} 的端口 {port} 超出范围，须在 1..=65535"));
            }
            ports.push(*port as u16);
        }
        if let PolicySubject::Group(name) = &from {
            if !doc.groups.iter().any(|g| &g.name == name) {
                return Err(format!("{at} 引用了未定义的 Group {name:?}"));
            }
        }
        if let PolicySubject::Group(name) = &to {
            if !doc.groups.iter().any(|g| &g.name == name) {
                return Err(format!("{at} 引用了未定义的 Group {name:?}"));
            }
        }
        doc.rules.push(PolicyRule { from, to, ports });
    }
    Ok(doc)
}

/// Policy 引用到的全部 User 名（规则两侧 + Group 成员）；存在性由调用方
/// 对照 users 表校验。
pub fn referenced_users(doc: &PolicyDoc) -> Vec<String> {
    let mut names = Vec::new();
    for rule in &doc.rules {
        for side in [&rule.from, &rule.to] {
            if let PolicySubject::User(name) = side {
                names.push(name.clone());
            }
        }
    }
    for group in &doc.groups {
        names.extend(group.users.iter().cloned());
    }
    names
}

/// 一个明文 IP 包的分类结果。Flow 是 TCP/UDP：两端地址、两端端口与协议号；
/// 出方向（TUN 读到）用于登记本地发起的流，入方向（写 TUN 前）用于过滤。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketClass {
    Flow {
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        /// TCP=6，UDP=17。
        proto: u8,
        /// TCP 的 flags 字节（SYN=0x02、ACK=0x10）；非 TCP 为 None。
        /// 仅 SYN 无 ACK 是新连接发起，其余属于已建立流。
        tcp_flags: Option<u8>,
    },
    /// 其他协议（如 ICMP）：只看源地址；可见即可 ping（ping 可见性跟随
    /// Map 可见性）。
    Other { src: IpAddr },
    /// 不是可解析的 IP 包：交给内核丢弃，过滤不介入。
    Malformed,
}

/// 从明文 IP 包提取过滤所需字段。只认 TCP(6)/UDP(17)，带扩展头的 IPv6
/// 按其他协议对待。
pub fn classify_packet(packet: &[u8]) -> PacketClass {
    let Some(&version_ihl) = packet.first() else {
        return PacketClass::Malformed;
    };
    let port_at = |offset: usize| -> Option<u16> {
        packet
            .get(offset..offset + 2)
            .map(|raw| u16::from_be_bytes(raw.try_into().expect("两字节切片必能转 u16")))
    };
    match version_ihl >> 4 {
        4 => {
            if packet.len() < 20 {
                return PacketClass::Malformed;
            }
            let ihl = (version_ihl & 0x0f) as usize * 4;
            if ihl < 20 || packet.len() < ihl {
                return PacketClass::Malformed;
            }
            let src: IpAddr = IpAddr::V4(packet[12..16].try_into().unwrap_or([0, 0, 0, 0]).into());
            let dst: IpAddr = IpAddr::V4(packet[16..20].try_into().unwrap_or([0, 0, 0, 0]).into());
            let ports = port_at(ihl).zip(port_at(ihl + 2));
            let flags = packet.get(ihl + 13).copied();
            let flow = |(src_port, dst_port): (u16, u16), proto: u8| PacketClass::Flow {
                src,
                dst,
                src_port,
                dst_port,
                proto,
                tcp_flags: (proto == 6).then_some(flags.unwrap_or(0)),
            };
            match packet[9] {
                6 => ports.map_or(PacketClass::Malformed, |p| flow(p, 6)),
                17 => ports.map_or(PacketClass::Malformed, |p| flow(p, 17)),
                _ => PacketClass::Other { src },
            }
        }
        6 => {
            if packet.len() < 40 {
                return PacketClass::Malformed;
            }
            let src: IpAddr = IpAddr::V6(packet[8..24].try_into().unwrap_or([0u8; 16]).into());
            let dst: IpAddr = IpAddr::V6(packet[24..40].try_into().unwrap_or([0u8; 16]).into());
            let ports = port_at(40).zip(port_at(42));
            let flags = packet.get(53).copied();
            let flow = |(src_port, dst_port): (u16, u16), proto: u8| PacketClass::Flow {
                src,
                dst,
                src_port,
                dst_port,
                proto,
                tcp_flags: (proto == 6).then_some(flags.unwrap_or(0)),
            };
            match packet[6] {
                6 => ports.map_or(PacketClass::Malformed, |p| flow(p, 6)),
                17 => ports.map_or(PacketClass::Malformed, |p| flow(p, 17)),
                _ => PacketClass::Other { src },
            }
        }
        _ => PacketClass::Malformed,
    }
}

/// 目标 Node 的入站过滤闸（A1）。两层判定：
/// 新入站连接（对端发起到我的端口）必须命中入站规则；我本地发起的流的
/// 回包（对端 → 我的客户端口）按出方向登记的流表放行——否则被允许的
/// 连接（dev→db:5432）也会死在对端 SYN-ACK 被我丢弃。ICMP 等其他协议
/// 跟随 Map 可见性（源是可见对端即放行）。规则之外默认拒绝（FR-10）。
pub struct InboundGate {
    state: Mutex<Option<InboundPolicyView>>,
    /// 出方向登记的流：(对端 node_id, proto, 本地端口, 对端端口) → 最近发包时刻。
    /// TCP 的新连接发起（仅 SYN）不查这张表：目标侧自己发出的回包与客户端
    /// 的新 SYN 共享同一四元组，只有 TCP flags 能区分方向语义。
    outbound_flows: Mutex<std::collections::HashMap<(String, u8, u16, u16), std::time::Instant>>,
    dropped: std::sync::atomic::AtomicU64,
}

/// 出方向流表项的 TTL：窗口内没有出方向包即过期（TCP 稳定流每包都会刷新）。
const FLOW_TTL: Duration = Duration::from_secs(60);

/// 单个 Node 视角的 Policy：Group 定义 + 该 Node 的入站规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundPolicyView {
    pub version: i64,
    pub groups: Vec<PolicyGroup>,
    pub rules: Vec<InboundRule>,
}

impl InboundPolicyView {
    /// 协议消息 → 领域形态。version 0（无 Policy）映射为 None；
    /// 解析不了的 from 主体丢弃该条（少一条规则 = 少一条放行，失败收敛）。
    pub fn from_proto(view: &hz_proto::PolicyView) -> Option<Self> {
        if view.version <= 0 {
            return None;
        }
        let rules = view
            .inbound_rules
            .iter()
            .filter_map(|rule| {
                let from = PolicySubject::parse(&rule.from)
                    .map_err(|reason| {
                        tracing::warn!(
                            %reason,
                            from = %rule.from,
                            "dropping unparseable inbound rule"
                        );
                    })
                    .ok()?;
                Some(InboundRule {
                    from,
                    ports: rule.ports.iter().map(|p| *p as u16).collect(),
                })
            })
            .collect();
        Some(Self {
            version: view.version,
            groups: view
                .groups
                .iter()
                .map(|group| PolicyGroup {
                    name: group.name.clone(),
                    users: group.users.clone(),
                })
                .collect(),
            rules,
        })
    }
}

/// 入站判定时对端的全部身份事实（Map 索引给出）。
pub struct PeerFacts<'a> {
    pub node_id: &'a str,
    pub owner_user: Option<&'a str>,
    pub tags: &'a [String],
}

impl Default for InboundGate {
    fn default() -> Self {
        Self::new()
    }
}

impl InboundGate {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
            outbound_flows: Mutex::new(std::collections::HashMap::new()),
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Map 流带来了新的 Policy 视图；None/版本 0 表示回到无 Policy 状态。
    pub fn update(&self, view: Option<InboundPolicyView>) {
        let effective = view.filter(|v| v.version > 0);
        let mut state = self.state.lock().expect("policy gate poisoned");
        if *state != effective {
            tracing::info!(
                version = effective.as_ref().map_or(0, |v| v.version),
                rules = effective.as_ref().map_or(0, |v| v.rules.len()),
                "inbound policy view updated"
            );
        }
        *state = effective;
    }

    pub fn version(&self) -> i64 {
        self.state
            .lock()
            .expect("policy gate poisoned")
            .as_ref()
            .map_or(0, |v| v.version)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 出方向（TUN 读到、即将封装发出的包）：登记本地发起的流，供回包放行。
    /// peer 是目的地址对应的对端；未知对端无需登记（入方向同样会被拒）。
    pub fn note_outbound(&self, class: PacketClass, peer: Option<&str>) {
        let PacketClass::Flow {
            proto,
            src_port,
            dst_port,
            ..
        } = class
        else {
            return;
        };
        let Some(peer) = peer else {
            return;
        };
        self.outbound_flows
            .lock()
            .expect("outbound flows poisoned")
            .insert(
                (peer.to_string(), proto, src_port, dst_port),
                Instant::now(),
            );
    }

    fn flow_is_reply(&self, peer: &str, proto: u8, local_port: u16, remote_port: u16) -> bool {
        let mut flows = self.outbound_flows.lock().expect("outbound flows poisoned");
        if flows.len() > 4096 {
            flows.retain(|_, seen| seen.elapsed() < FLOW_TTL);
        }
        match flows.get_mut(&(peer.to_string(), proto, local_port, remote_port)) {
            Some(seen) if seen.elapsed() <= FLOW_TTL => {
                *seen = Instant::now();
                true
            }
            _ => false,
        }
    }

    /// 仅 SYN 不含 ACK = 新的入站连接发起。
    fn is_new_connection(class: &PacketClass) -> bool {
        matches!(
            class,
            PacketClass::Flow { proto: 6, tcp_flags: Some(flags), .. }
                if flags & 0x02 != 0 && flags & 0x10 == 0
        )
    }

    /// 判定一个解密后的明文包是否放行写入 TUN。
    pub fn admit(&self, class: PacketClass, peer: Option<PeerFacts<'_>>) -> bool {
        let state = self.state.lock().expect("policy gate poisoned");
        let Some(policy) = state.as_ref() else {
            return true;
        };
        match class {
            PacketClass::Malformed => true,
            PacketClass::Other { .. } => {
                // ICMP 等跟随 Map 可见性：包能从在册对端解密而来即视为可见。
                if peer.is_none() {
                    self.count_drop();
                    return false;
                }
                true
            }
            PacketClass::Flow {
                dst_port,
                src_port,
                proto,
                ..
            } => {
                let Some(peer) = peer else {
                    self.count_drop();
                    return false;
                };
                let rule_allows = policy.rules.iter().any(|rule| {
                    rule.from
                        .matches(&policy.groups, peer.owner_user, peer.tags)
                        && rule.ports.contains(&dst_port)
                });
                let allowed = rule_allows
                    || (!Self::is_new_connection(&class)
                        && self.flow_is_reply(peer.node_id, proto, dst_port, src_port));
                if !allowed {
                    self.count_drop();
                }
                allowed
            }
        }
    }

    fn count_drop(&self) {
        let dropped = self
            .dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if dropped == 0 || (dropped + 1) % 100 == 0 {
            tracing::warn!(dropped = dropped + 1, "inbound packet dropped by policy");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(content: &str) -> PolicyDoc {
        parse_policy(content).unwrap()
    }

    const DEV_DB: &str = r#"
version = 1

[[group]]
name = "dev"
users = ["alice"]

[[rule]]
from = "group:dev"
to = "tag:db"
ports = [5432]
"#;

    #[test]
    fn parse_accepts_pinned_shape_and_roundtrips_subjects() {
        let parsed = doc(DEV_DB);
        assert_eq!(parsed.version, Some(1));
        assert_eq!(
            parsed.groups,
            vec![PolicyGroup {
                name: "dev".to_string(),
                users: vec!["alice".to_string()]
            }]
        );
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].from.to_text(), "group:dev");
        assert_eq!(parsed.rules[0].to.to_text(), "tag:db");
        assert_eq!(parsed.rules[0].ports, vec![5432]);
        assert_eq!(
            referenced_users(&parsed),
            vec!["alice".to_string()],
            "Group 成员与 user: 引用都要进存在性校验名单"
        );
    }

    #[test]
    fn parse_rejects_each_structural_violation_with_readable_reason() {
        let cases = [
            ("not toml at all [[", "TOML 解析失败"),
            (
                "[[rule]]\nfrom = \"group:dev\"\nto = \"tag:db\"\nports = [5432]",
                "未定义的 Group",
            ),
            (
                "[[rule]]\nfrom = \"grp:dev\"\nto = \"tag:db\"\nports = [80]",
                "缺少前缀",
            ),
            (
                "[[rule]]\nfrom = \"tag:Bad_Tag\"\nto = \"tag:db\"\nports = [80]",
                "不符合",
            ),
            (
                "[[rule]]\nfrom = \"tag:ok\"\nto = \"tag:db\"\nports = [0]",
                "超出范围",
            ),
            (
                "[[rule]]\nfrom = \"tag:ok\"\nto = \"tag:db\"\nports = []",
                "ports 为空",
            ),
            (
                "[[group]]\nname = \"dup\"\nusers = []\n[[group]]\nname = \"dup\"\nusers = []",
                "重复",
            ),
            (
                "[[rule]]\nfrm = \"tag:ok\"\nto = \"tag:db\"\nports = [80]",
                "TOML 解析失败",
            ),
        ];
        for (content, expected_fragment) in cases {
            let error = parse_policy(content).unwrap_err();
            assert!(
                error.contains(expected_fragment),
                "{content:?} 的报错应含 {expected_fragment:?}，实际 {error:?}"
            );
        }
    }

    #[test]
    fn parse_accepts_empty_rule_list_as_lockdown() {
        let parsed = doc("[[group]]\nname = \"dev\"\nusers = [\"alice\"]\n");
        assert!(parsed.rules.is_empty(), "空规则列表应合法（等于全拒绝）");
    }

    fn tags(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pair_visibility_follows_rules_in_either_direction() {
        let policy = doc(DEV_DB);
        let no_tags = tags(&[]);
        let db_tags = tags(&["db"]);
        let alice = (Some("alice"), no_tags.as_slice());
        let bob = (Some("bob"), no_tags.as_slice());
        let db = (None, db_tags.as_slice());
        assert!(policy.pair_connected(alice, db), "dev 成员与 db 互通");
        assert!(
            policy.pair_connected(db, alice),
            "方向无关：db 也看见 dev 成员"
        );
        assert!(!policy.pair_connected(alice, bob), "规则之外默认拒绝");
        assert!(!policy.pair_connected(bob, db), "非 dev 成员不可见 db");
    }

    #[test]
    fn inbound_rules_pick_to_side_matches() {
        let policy = doc(DEV_DB);
        let db_tags = tags(&["db"]);
        let inbound = policy.inbound_rules_for((None, db_tags.as_slice()));
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].from.to_text(), "group:dev");
        assert_eq!(inbound[0].ports, vec![5432]);
        let no_tags = tags(&[]);
        assert!(
            policy
                .inbound_rules_for((Some("alice"), no_tags.as_slice()))
                .is_empty(),
            "规则 to 侧不命中 alice 的 Node，无入站规则"
        );
    }

    fn tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    fn udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    fn icmp_packet(src: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src);
        packet
    }

    fn ipv6_tcp_packet(dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[6] = 6;
        packet[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40..42].copy_from_slice(&40000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    fn gate_with_dev_db() -> InboundGate {
        let policy = doc(DEV_DB);
        let db_tags = tags(&["db"]);
        let gate = InboundGate::new();
        gate.update(Some(InboundPolicyView {
            version: 1,
            groups: policy.groups.clone(),
            rules: policy.inbound_rules_for((None, db_tags.as_slice())),
        }));
        gate
    }

    const ALICE_IP: [u8; 4] = [100, 96, 0, 2];
    const BOB_IP: [u8; 4] = [100, 96, 0, 3];
    const DB_IP: [u8; 4] = [100, 96, 0, 4];

    fn peer_alice<'a>(no_tags: &'a Vec<String>) -> PeerFacts<'a> {
        PeerFacts {
            node_id: "node-alice",
            owner_user: Some("alice"),
            tags: no_tags.as_slice(),
        }
    }

    fn peer_bob<'a>(no_tags: &'a Vec<String>) -> PeerFacts<'a> {
        PeerFacts {
            node_id: "node-bob",
            owner_user: Some("bob"),
            tags: no_tags.as_slice(),
        }
    }

    #[test]
    fn classify_reads_both_ends_and_family() {
        match classify_packet(&tcp_packet(ALICE_IP, DB_IP, 40000, 5432)) {
            PacketClass::Flow {
                src,
                dst,
                src_port,
                dst_port,
                proto,
                tcp_flags,
            } => {
                assert_eq!(src.to_string(), "100.96.0.2");
                assert_eq!(dst.to_string(), "100.96.0.4");
                assert_eq!(src_port, 40000);
                assert_eq!(dst_port, 5432);
                assert_eq!(proto, 6);
                assert!(tcp_flags.is_some(), "TCP 要带 flags");
            }
            other => panic!("TCP 包应分类为 Flow：{other:?}"),
        }
        match classify_packet(&udp_packet(ALICE_IP, DB_IP, 5353, 53)) {
            PacketClass::Flow {
                dst_port,
                proto,
                tcp_flags,
                ..
            } => {
                assert_eq!(dst_port, 53);
                assert_eq!(proto, 17);
                assert!(tcp_flags.is_none(), "UDP 不带 TCP flags");
            }
            other => panic!("UDP 包应分类为 Flow：{other:?}"),
        }
        assert!(matches!(
            classify_packet(&icmp_packet(ALICE_IP)),
            PacketClass::Other { .. }
        ));
        match classify_packet(&ipv6_tcp_packet(22)) {
            PacketClass::Flow { src, dst_port, .. } => {
                assert!(src.is_ipv6());
                assert_eq!(dst_port, 22);
            }
            other => panic!("IPv6 TCP 包应分类为 Flow：{other:?}"),
        }
        assert_eq!(classify_packet(&[]), PacketClass::Malformed);
        assert_eq!(classify_packet(&[0x45, 0, 0]), PacketClass::Malformed);
    }

    #[test]
    fn gate_allows_without_policy_and_enforces_once_present() {
        let gate = InboundGate::new();
        let no_tags = tags(&[]);
        assert!(
            gate.admit(
                classify_packet(&tcp_packet(ALICE_IP, DB_IP, 40000, 22)),
                Some(peer_alice(&no_tags))
            ),
            "未收到任何 Policy 前全互通"
        );

        let gate = gate_with_dev_db();
        assert!(gate.admit(
            classify_packet(&tcp_packet(ALICE_IP, DB_IP, 40000, 5432)),
            Some(peer_alice(&no_tags))
        ));
        assert!(!gate.admit(
            classify_packet(&tcp_packet(ALICE_IP, DB_IP, 40000, 22)),
            Some(peer_alice(&no_tags))
        ));
        assert_eq!(gate.dropped(), 1, "拒绝要计数");
        assert!(!gate.admit(
            classify_packet(&tcp_packet(BOB_IP, DB_IP, 40000, 5432)),
            Some(peer_bob(&no_tags))
        ));
        assert!(
            !gate.admit(
                classify_packet(&tcp_packet([100, 96, 0, 9], DB_IP, 40000, 5432)),
                None
            ),
            "Policy 下未知源一律拒绝"
        );
        assert!(
            gate.admit(
                classify_packet(&icmp_packet(ALICE_IP)),
                Some(peer_alice(&no_tags))
            ),
            "非 TCP/UDP 跟随可见性：可见即可 ping"
        );
        assert!(
            gate.admit(
                classify_packet(&icmp_packet(BOB_IP)),
                Some(peer_bob(&no_tags))
            ),
            "ICMP 只看可见性：bob 若在 Map 里也可 ping（可见性由服务端过滤保证）"
        );
        assert_eq!(gate.dropped(), 3, "22 端口、bob 的 5432、未知源各计一次");
    }

    #[test]
    fn replies_to_locally_initiated_flows_pass_but_new_connections_do_not() {
        let gate = gate_with_dev_db();
        let no_tags = tags(&[]);

        // alice 向 db:5432 发起（出方向登记），db 回包到 alice:40000。
        let outbound = classify_packet(&tcp_packet(ALICE_IP, DB_IP, 40000, 5432));
        let alice_gate_side = classify_packet(&tcp_packet(DB_IP, ALICE_IP, 5432, 40000));
        let _ = alice_gate_side;
        gate.note_outbound(outbound, Some("db"));
        let reply = classify_packet(&tcp_packet(DB_IP, ALICE_IP, 5432, 40000));
        assert!(
            gate.admit(
                reply,
                Some(PeerFacts {
                    node_id: "db",
                    owner_user: None,
                    tags: tags(&["db"]).as_slice(),
                })
            ),
            "被允许连接的 SYN-ACK 回包必须放行"
        );

        // 同一机制在目标侧不豁免新连接：alice 直连 db:22 的 SYN 在 db 侧
        // 无规则也无出方向登记，仍被拒。
        assert!(!gate.admit(
            classify_packet(&tcp_packet(ALICE_IP, DB_IP, 40000, 22)),
            Some(peer_alice(&no_tags))
        ));

        // UDP 查询回包同理。
        let outbound = classify_packet(&udp_packet(BOB_IP, DB_IP, 5353, 53));
        let _ = outbound;
        let reply = classify_packet(&udp_packet(DB_IP, BOB_IP, 53, 5353));
        assert!(
            !gate.admit(reply, Some(peer_bob(&no_tags))),
            "未登记的流回包不放行"
        );
    }

    #[test]
    fn new_syn_on_established_tuple_still_needs_a_rule() {
        // 目标侧的回包与客户端的新 SYN 共享四元组：回包放行靠 TCP flags
        // 区分（仅 SYN 无 ACK = 新连接，只查规则）。回滚收紧后新 SYN 必须
        // 重新被拒。
        let gate = gate_with_dev_db();
        let no_tags = tags(&[]);
        let syn = |src_port: u16, dst_port: u16| {
            let mut packet = tcp_packet(ALICE_IP, DB_IP, src_port, dst_port);
            packet[33] = 0x02; // SYN
            classify_packet(&packet)
        };
        let non_syn = |src_port: u16, dst_port: u16| {
            let mut packet = tcp_packet(DB_IP, ALICE_IP, src_port, dst_port);
            packet[33] = 0x18; // PSH|ACK
            classify_packet(&packet)
        };

        assert!(
            !gate.admit(syn(40000, 22), Some(peer_alice(&no_tags))),
            "22 的新 SYN 只查规则：被拒"
        );
        // 已登记流的后续包（对端回包）放行。
        let outbound = syn(40000, 5432);
        gate.note_outbound(outbound, Some("db"));
        let mut reply_packet = tcp_packet(DB_IP, ALICE_IP, 5432, 40000);
        reply_packet[33] = 0x02 | 0x10; // SYN|ACK
        assert!(
            gate.admit(
                classify_packet(&reply_packet),
                Some(PeerFacts {
                    node_id: "db",
                    owner_user: None,
                    tags: tags(&["db"]).as_slice(),
                })
            ),
            "SYN-ACK 回包（含 ACK 位）按流表放行"
        );
        assert!(
            gate.admit(
                non_syn(5432, 40000),
                Some(PeerFacts {
                    node_id: "db",
                    owner_user: None,
                    tags: tags(&["db"]).as_slice(),
                })
            ),
            "已建立流的纯 ACK/数据包放行"
        );
    }

    #[test]
    fn gate_back_to_open_when_view_cleared() {
        let gate = gate_with_dev_db();
        gate.update(None);
        let no_tags = tags(&[]);
        assert!(gate.admit(
            classify_packet(&tcp_packet(BOB_IP, DB_IP, 40000, 22)),
            Some(peer_bob(&no_tags))
        ));
        assert_eq!(gate.version(), 0);
    }
}
