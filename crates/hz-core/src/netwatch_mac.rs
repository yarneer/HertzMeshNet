//! macOS 的物理出口监视（FR-7）：轮询 [`crate::netif::physical_egress`]，
//! 出口变化（Wi-Fi ↔ 以太网、网卡升降）时发出事件。类型保持在本模块
//! （macOS cfg 私有），Linux 侧的监视与共享的跨平台事件形状在 #9 的
//! netwatch 落地；届时两边的重绑消费在同一处合流。
//! `route -n monitor` 能做到事件驱动，但解析其无版本承诺的输出不如
//! 5 秒轮询直接，先轮询。

use tokio::sync::mpsc;

/// 轮询周期。
const POLL_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// 一次出口变化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressEvent {
    /// 物理出口从一张网卡换到另一张（任一侧可能探测不到）。
    Changed {
        from: Option<String>,
        to: Option<String>,
    },
}

/// 两次探测结果 → 变化事件；结果相同（含同为 None）返回 None。
fn change_of(current: &Option<String>, seen: &Option<String>) -> Option<EgressEvent> {
    if current == seen {
        return None;
    }
    Some(EgressEvent::Changed {
        from: current.clone(),
        to: seen.clone(),
    })
}

/// 起后台任务：每 5 秒探测一次物理出口，变化时发事件并记日志。
/// 接收端掉线即退出。新创建的 socket 在建立时绑定新出口（netif）；
/// 已有长连 socket 的重绑随跨平台监视合流后统一处理。
pub fn spawn_watcher() -> mpsc::Receiver<EgressEvent> {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut current = crate::netif::physical_egress();
        let mut ticker = tokio::time::interval(POLL_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let seen = crate::netif::physical_egress();
            let Some(event) = change_of(&current, &seen) else {
                continue;
            };
            tracing::warn!(from = ?current, to = ?seen, "physical egress interface changed");
            current = seen;
            if tx.send(event).await.is_err() {
                return;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_of_reports_only_actual_flips() {
        assert_eq!(change_of(&None, &None), None, "两侧都探测不到不算变化");
        assert_eq!(
            change_of(&Some("en0".to_string()), &Some("en0".to_string())),
            None,
            "同一张网卡不算变化"
        );
        assert_eq!(
            change_of(&Some("en0".to_string()), &Some("en4".to_string())),
            Some(EgressEvent::Changed {
                from: Some("en0".to_string()),
                to: Some("en4".to_string()),
            })
        );
        assert_eq!(
            change_of(&Some("en0".to_string()), &None),
            Some(EgressEvent::Changed {
                from: Some("en0".to_string()),
                to: None,
            }),
            "物理出口消失（全成虚拟网卡）也要发事件"
        );
    }
}
