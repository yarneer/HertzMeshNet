//! 本机网络变化侦测（FR-8 网络变化后自动恢复）。侦测分两层：
//! `ip monitor link address route` 子进程给出即时唤醒（事件只当唤醒提示用，
//! 不解析细节——权威判定永远是 [`egress_snapshot`] 的前后差异，这样命名空间、
//! 容器等 netlink 事件形态各异的环境与正常环境走同一条判定路径）；
//! 每 5 秒轮询 [`egress_snapshot`] 作为兜底（monitor 不可用或漏事件时仍能收敛）。
//! 单调时钟落后墙钟超过 [`WAKE_DRIFT`] 判为休眠唤醒（Linux 的
//! CLOCK_MONOTONIC 不计入挂起时间，唤醒后墙钟已走了而单调时钟没有）。
//! 事件经 1 秒去抖后发出：换网卡在内核里是 link/addr/route 一串连发，
//! 消费者（hzd 的恢复序列）应只见一次落定的事件。
//!
//! macOS 的 watcher（System Configuration 动态存储）与 IP_BOUND_IF 随
//! macOS 数据面票据（#16）接入；本模块在 macOS 上不产生事件。

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::mpsc;

/// 网络变化事件（去抖后）。变体只影响日志粒度，消费者一律重算快照再决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetEvent {
    LinkChanged,
    AddrChanged,
    RouteChanged,
    /// 单调时钟落后墙钟超过阈值：休眠唤醒。NAT 映射大概率已失效，
    /// 即使快照没变也应重走恢复序列。
    ClockJump,
}

/// 判为唤醒的单调/墙钟偏差。
#[cfg(target_os = "linux")]
const WAKE_DRIFT: Duration = Duration::from_secs(30);

/// 事件去抖窗口：静默满此时长才把积攒的事件发出。
#[cfg(target_os = "linux")]
const DEBOUNCE: Duration = Duration::from_secs(1);

/// 快照轮询周期（netlink 之外的兜底）。
#[cfg(target_os = "linux")]
const POLL_EVERY: Duration = Duration::from_secs(5);

/// 事件队列容量。消费者（hzd 恢复序列）毫秒级排空，容量只防瞬峰。
const EVENT_QUEUE: usize = 64;

/// 侦测用的网络状态快照：物理出口网卡 + 非虚拟网卡的地址集合。
/// 任一变化即视为本机网络变化。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressSnapshot {
    pub iface: Option<String>,
    pub addrs: Vec<IpAddr>,
}

/// 取一次快照。物理出口探测失败（无路由、全虚拟网卡、非 Linux）时
/// iface 为 None；地址集合仍参与比对（例如地址整体消失）。
pub fn egress_snapshot() -> EgressSnapshot {
    EgressSnapshot {
        iface: crate::netif::physical_egress(),
        addrs: crate::endpoint::interface_addrs(),
    }
}

/// 两份快照是否有差异（出口网卡或地址集合变化）。地址视作集合比对。
pub fn snapshot_changed(before: &EgressSnapshot, after: &EgressSnapshot) -> bool {
    before.iface != after.iface
        || before.addrs.len() != after.addrs.len()
        || before.addrs.iter().any(|addr| !after.addrs.contains(addr))
}

/// 依差异归类事件变体：出口网卡变了是链路级变化，否则是地址变化。
#[cfg(target_os = "linux")]
fn event_of_diff(before: &EgressSnapshot, after: &EgressSnapshot) -> NetEvent {
    if before.iface != after.iface {
        NetEvent::LinkChanged
    } else {
        NetEvent::AddrChanged
    }
}

/// 单调/墙钟对，检测休眠唤醒。
#[cfg(target_os = "linux")]
struct ClockDrift {
    mono: Instant,
    wall: SystemTime,
}

#[cfg(target_os = "linux")]
impl ClockDrift {
    fn new() -> Self {
        Self {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    /// 检查并消费：判为唤醒后重置基线（否则唤醒后的每次检查都会重复触发）。
    fn jumped(&mut self) -> bool {
        let jumped = is_wake(self.mono.elapsed(), self.wall.elapsed().unwrap_or_default());
        if jumped {
            self.mono = Instant::now();
            self.wall = SystemTime::now();
        }
        jumped
    }
}

/// 唤醒判定：墙钟走过的时长比单调时钟多出 [`WAKE_DRIFT`] 以上。
/// 常规运行中两者偏差是纳秒级的时钟精度差，不会接近该阈值。
#[cfg(target_os = "linux")]
fn is_wake(mono_elapsed: Duration, wall_elapsed: Duration) -> bool {
    wall_elapsed.saturating_sub(mono_elapsed) > WAKE_DRIFT
}

/// 启动网络侦测，返回去抖后的事件流。接收端被丢弃时侦测任务自动结束。
/// 事件只在快照真的变化（或休眠唤醒）时发出；netlink 的原始事件只是唤醒提示。
///
/// 非 Linux 平台不产生事件：通道随即关闭，消费者的恢复循环自然退出。
pub fn spawn() -> mpsc::Receiver<NetEvent> {
    let (tx, rx) = mpsc::channel(EVENT_QUEUE);
    #[cfg(target_os = "linux")]
    tokio::spawn(watcher(tx));
    #[cfg(not(target_os = "linux"))]
    drop(tx);
    rx
}

/// Linux 侦测主循环：monitor 子进程的行是唤醒提示；轮询做权威差异比对；
/// 去抖满 1 秒静默才把这一串事件发出去。
#[cfg(target_os = "linux")]
async fn watcher(tx: mpsc::Sender<NetEvent>) {
    let mut monitor = Monitor::spawn();
    let mut last = egress_snapshot();
    let mut drift = ClockDrift::new();
    let mut pending: Vec<NetEvent> = Vec::new();
    let mut quiet_until: Option<Instant> = None;
    let mut poll = tokio::time::interval(POLL_EVERY);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let flush = async {
            match quiet_until {
                None => std::future::pending::<()>().await,
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
            }
        };
        tokio::select! {
            line = monitor.next_line() => {
                if let Some(event) = line.and_then(|text| classify_monitor_line(&text)) {
                    if !pending.contains(&event) {
                        pending.push(event);
                    }
                    quiet_until = Some(Instant::now() + DEBOUNCE);
                }
            }
            _ = poll.tick() => {
                if drift.jumped() && !pending.contains(&NetEvent::ClockJump) {
                    pending.push(NetEvent::ClockJump);
                    quiet_until = Some(Instant::now() + DEBOUNCE);
                }
                let current = egress_snapshot();
                if snapshot_changed(&last, &current) {
                    let event = event_of_diff(&last, &current);
                    if !pending.contains(&event) {
                        pending.push(event);
                        quiet_until = Some(Instant::now() + DEBOUNCE);
                    }
                }
                last = current;
            }
            _ = flush => {
                quiet_until = None;
                for event in pending.drain(..) {
                    tracing::debug!(?event, "net event settled");
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// `ip monitor link address route` 子进程的行读取器。进程退出（容器里
/// iproute2 缺失、被杀）时休整一个轮询周期后重拉；重拉失败进入 Dead 态，
/// 之后 next_line 永远挂起，侦测退化为纯轮询兜底。
#[cfg(target_os = "linux")]
enum Monitor {
    Lines(tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>),
    Dead,
}

#[cfg(target_os = "linux")]
impl Monitor {
    fn spawn() -> Self {
        Self::spawn_inner().unwrap_or_else(|error| {
            tracing::warn!(%error, "ip monitor unavailable, falling back to poll only");
            Self::Dead
        })
    }

    fn spawn_inner() -> anyhow::Result<Self> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let child = tokio::process::Command::new("ip")
            .args(["monitor", "link", "address", "route"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            // 侦测任务结束时别把 monitor 进程留在系统里。
            .kill_on_drop(true)
            .spawn()?;
        let stdout = child.stdout.expect("piped above");
        Ok(Self::Lines(BufReader::new(stdout).lines()))
    }

    async fn next_line(&mut self) -> Option<String> {
        loop {
            match self {
                Self::Lines(lines) => {
                    // next_line 是 tokio::io::Lines 的固有方法，无需 trait 导入。
                    match lines.next_line().await {
                        Ok(Some(line)) => return Some(line),
                        Ok(None) => {
                            tokio::time::sleep(POLL_EVERY).await;
                            *self = Self::spawn_inner().unwrap_or(Self::Dead);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "ip monitor read failed");
                            *self = Self::Dead;
                            return None;
                        }
                    }
                }
                Self::Dead => std::future::pending().await,
            }
        }
    }
}

/// `ip monitor` 行分类。行样例：
///   link: `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...`
///   addr: `2: eth0    inet 192.168.1.4/24 brd ... scope global eth0`
///   route: `default via 203.0.113.1 dev eth0 proto static`（无 ifindex 前缀）
/// 删除事件带 `Deleted ` 前缀。分类只影响日志粒度，识别不了按路由变化处理。
#[cfg(target_os = "linux")]
fn classify_monitor_line(line: &str) -> Option<NetEvent> {
    let line = line.strip_prefix("Deleted ").unwrap_or(line);
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    let ifindex = first.strip_suffix(':').unwrap_or("");
    if ifindex.is_empty() || !ifindex.chars().all(|c| c.is_ascii_digit()) {
        return Some(NetEvent::RouteChanged);
    }
    let second = fields.next()?;
    if second.ends_with(':') {
        Some(NetEvent::LinkChanged)
    } else {
        Some(NetEvent::AddrChanged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(iface: Option<&str>, addrs: &[&str]) -> EgressSnapshot {
        EgressSnapshot {
            iface: iface.map(str::to_string),
            addrs: addrs.iter().map(|text| text.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn snapshot_change_detects_iface_addr_and_set_membership() {
        let before = snapshot(Some("eth0"), &["192.168.1.4", "192.168.1.5"]);
        assert!(!snapshot_changed(
            &before,
            &snapshot(Some("eth0"), &["192.168.1.5", "192.168.1.4"])
        ));
        assert!(snapshot_changed(
            &before,
            &snapshot(Some("wlan0"), &["192.168.1.4", "192.168.1.5"])
        ));
        assert!(snapshot_changed(
            &before,
            &snapshot(Some("eth0"), &["192.168.1.4"])
        ));
        assert!(snapshot_changed(
            &before,
            &snapshot(Some("eth0"), &["192.168.1.4", "10.0.0.9"])
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn event_of_diff_names_iface_moves_as_link_changes() {
        let eth = snapshot(Some("eth0"), &[]);
        assert_eq!(
            event_of_diff(&eth, &snapshot(Some("wlan0"), &[])),
            NetEvent::LinkChanged
        );
        assert_eq!(
            event_of_diff(&eth, &snapshot(Some("eth0"), &["10.0.0.9"])),
            NetEvent::AddrChanged
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wake_needs_wall_clock_far_ahead_of_monotonic() {
        assert!(!is_wake(Duration::from_secs(10), Duration::from_secs(10)));
        // NTP 校时或时钟精度差在秒级以内，不构成唤醒。
        assert!(!is_wake(Duration::from_secs(10), Duration::from_secs(15)));
        assert!(is_wake(Duration::from_secs(2), Duration::from_secs(3600)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clock_drift_resets_baseline_after_a_jump() {
        let mut drift = ClockDrift::new();
        assert!(!drift.jumped());
        drift.wall = SystemTime::now() - Duration::from_secs(3600);
        assert!(drift.jumped());
        // 基线已重置：紧接着的检查不再触发。
        assert!(!drift.jumped());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monitor_lines_classify_to_their_event_kind() {
        assert_eq!(
            classify_monitor_line(
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP"
            ),
            Some(NetEvent::LinkChanged)
        );
        assert_eq!(
            classify_monitor_line("2: eth0    inet 192.168.12.30/24 scope global eth0"),
            Some(NetEvent::AddrChanged)
        );
        assert_eq!(
            classify_monitor_line(
                "Deleted 192.168.11.0/24 dev eth0 proto kernel scope link src 192.168.11.10"
            ),
            Some(NetEvent::RouteChanged)
        );
        assert_eq!(
            classify_monitor_line("default via 203.0.113.1 dev eth0"),
            Some(NetEvent::RouteChanged)
        );
        assert_eq!(classify_monitor_line(""), None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn spawn_emits_nothing_on_a_quiet_host() {
        // 静止主机（快照不变化）不应产生事件；首个轮询去抖也早于该窗口。
        let mut events = spawn();
        let seen = tokio::time::timeout(DEBOUNCE * 2, events.recv()).await;
        assert!(seen.is_err(), "静止时不应有事件");
    }
}
