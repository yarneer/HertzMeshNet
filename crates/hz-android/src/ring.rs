//! 2000 行内存环形日志缓冲（规格 §6）：tracing layer 同时写 logcat 与本
//! 缓冲，`diagnostics` 的 log_tail 取自这里。逐行经
//! `hz_engine::diagnostics::redact_line` 脱敏后入环。

use std::collections::VecDeque;

/// 环形缓冲容量（行）。
pub const RING_CAPACITY: usize = 2000;

/// 线程安全的环形日志。写入端是 tracing layer（高频），读取端是
/// `diagnostics`（低频）；一把互斥锁足够。
pub struct RingLog {
    lines: std::sync::Mutex<VecDeque<String>>,
    capacity: usize,
}

impl RingLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            lines: std::sync::Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// 脱敏后写入一行（容量满时丢最老的）。
    pub fn push_line(&self, line: String) {
        let redacted = hz_engine::diagnostics::redact_line(&line);
        let mut lines = self.lines.lock().expect("ring log poisoned");
        if lines.len() >= self.capacity {
            lines.pop_front();
        }
        lines.push_back(redacted);
    }

    /// 当前缓冲快照（脱敏后的行，含说明）。
    pub fn tail_lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .expect("ring log poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_drops_oldest_and_redacts() {
        let log = RingLog::new(3);
        for i in 0..5 {
            log.push_line(format!("line {i}"));
        }
        let lines = log.tail_lines();
        assert_eq!(lines, vec!["line 2", "line 3", "line 4"]);

        // 私钥形态的行被脱敏（#101 验收：诊断不含私钥）。
        log.push_line("auth key hznet.AAAAABBBBCCCCDDDDaaaaa".into());
        assert!(
            log.tail_lines().last().unwrap().contains("[REDACTED]"),
            "Auth Key 必须脱敏"
        );
    }
}
