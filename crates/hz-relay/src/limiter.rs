//! 每 Node 的 Relay 入口限速（FR-9）：令牌桶，bytes/s = rate_mbps × 125_000，
//! 突发容量为 1 秒额度。作用在 forward_data 的发送方预算上（入口 policing）；
//! 超额帧直接丢弃——WireGuard 自带重传，丢帧只会降速不会破坏语义。
//! 时间由调用方注入，可全平台单测。

use std::collections::HashMap;
use std::time::Instant;

/// 1 Mbps 对应的字节数。
const BYTES_PER_MBPS: u64 = 125_000;

struct Bucket {
    tokens: f64,
    updated: Instant,
}

pub struct Limiter {
    rate_bytes_per_sec: f64,
    burst: f64,
    buckets: HashMap<String, Bucket>,
}

impl Limiter {
    pub fn new(rate_mbps: u64) -> Self {
        let rate_bytes_per_sec = (rate_mbps.max(1) * BYTES_PER_MBPS) as f64;
        Self {
            rate_bytes_per_sec,
            burst: rate_bytes_per_sec,
            buckets: HashMap::new(),
        }
    }

    pub fn rate_mbps(&self) -> u64 {
        (self.rate_bytes_per_sec / BYTES_PER_MBPS as f64) as u64
    }

    /// 判定一个入站帧是否放行：按发送 Node 的桶扣减令牌。
    /// 桶空时整帧丢弃（不部分放行，保持 UDP 数据报语义）。
    pub fn admit(&mut self, node_id: &str, bytes: usize, now: Instant) -> bool {
        let rate = self.rate_bytes_per_sec;
        let burst = self.burst;
        let bucket = self.buckets.entry(node_id.to_owned()).or_insert(Bucket {
            tokens: burst,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.updated = now;
        if bucket.tokens >= bytes as f64 {
            bucket.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_drop_then_refill() {
        let mut limiter = Limiter::new(1); // 125_000 B/s，桶容量 125_000
        let t0 = Instant::now();
        assert!(limiter.admit("n1", 60_000, t0), "首个帧在突发额度内");
        assert!(
            !limiter.admit("n1", 70_000, t0),
            "桶只剩 65_000，超出容量的帧应被丢弃"
        );
        assert!(
            limiter.admit("n1", 125_000, t0 + Duration::from_secs(1)),
            "静默 1 秒后桶恢复满额"
        );
    }

    #[test]
    fn steady_stream_over_limit_loses_frames() {
        // 2 Mbps = 250_000 B/s，桶 250_000。每 100ms 发 30_000 B（300_000 B/s，
        // 超限 20%）。净消耗每周期 5_000 B，第 41 个周期桶见底开始丢弃；
        // 之后丢弃与放行交替，放行总量收敛到 补充量 59×25_000 附近。
        let mut limiter = Limiter::new(2);
        let t0 = Instant::now();
        let mut admitted = 0usize;
        let mut dropped = 0usize;
        for i in 0..60 {
            let at = t0 + Duration::from_millis(100 * i);
            if limiter.admit("n1", 30_000, at) {
                admitted += 30_000;
            } else {
                dropped += 30_000;
            }
        }
        assert!(dropped > 0, "超限流量必须被丢弃");
        // 上界（守恒）：桶初始 250_000 + 59 周期补充 1_475_000。
        assert!(
            admitted <= 250_000 + 59 * 25_000,
            "放行量 {admitted} 超过桶加补充的上界"
        );
        // 下界：限速不饿死——补充的令牌最终都被用掉。
        assert!(
            admitted >= 59 * 25_000,
            "放行量 {admitted} 低于补充速率，节点被饿死"
        );
    }

    #[test]
    fn budgets_are_per_node() {
        let mut limiter = Limiter::new(1);
        let t0 = Instant::now();
        assert!(limiter.admit("a", 125_000, t0));
        assert!(limiter.admit("b", 125_000, t0), "不同 Node 的预算互相独立");
        assert_eq!(limiter.rate_mbps(), 1);
    }
}
