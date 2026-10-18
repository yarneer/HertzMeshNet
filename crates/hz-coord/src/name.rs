//! Node Name 规范化与去重（FR-4）：默认取主机名，小写、仅 [a-z0-9-]，
//! 重名时加 -2、-3 后缀。

pub const MAX_NAME_LEN: usize = 63;
const MAX_SUFFIX: u32 = 99;

pub struct NodeName;

impl NodeName {
    pub fn normalize(hostname: &str) -> String {
        let mut out = String::with_capacity(hostname.len());
        let mut last_was_dash = false;
        for c in hostname.chars() {
            let mapped = if c.is_ascii_lowercase() || c.is_ascii_digit() {
                Some(c)
            } else if c.is_ascii_uppercase() {
                Some(c.to_ascii_lowercase())
            } else {
                None
            };
            match mapped {
                Some(c) => {
                    out.push(c);
                    last_was_dash = false;
                }
                None if !last_was_dash => {
                    out.push('-');
                    last_was_dash = true;
                }
                None => {}
            }
        }
        let trimmed = out.trim_matches('-');
        if trimmed.is_empty() {
            "node".to_string()
        } else {
            trimmed.chars().take(MAX_NAME_LEN).collect()
        }
    }

    /// 依次尝试 `base`、`base-2`、…、`base-99`，返回第一个未被占用的名字。
    pub fn dedupe(base: &str, is_taken: impl Fn(&str) -> bool) -> Option<String> {
        if !is_taken(base) {
            return Some(base.to_string());
        }
        for n in 2..=MAX_SUFFIX {
            let candidate = format!("{base}-{n}");
            if !is_taken(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn normalizes_hostname_literals() {
        assert_eq!(NodeName::normalize("My Host_01!"), "my-host-01");
        assert_eq!(
            NodeName::normalize("MacBook-Pro.local"),
            "macbook-pro-local"
        );
        assert_eq!(NodeName::normalize("--"), "node");
        assert_eq!(NodeName::normalize(""), "node");
        assert_eq!(NodeName::normalize("a---b"), "a-b");
        assert_eq!(NodeName::normalize("服务器"), "node");
    }

    #[test]
    fn truncates_to_63_chars() {
        let long = "a".repeat(100);
        let normalized = NodeName::normalize(&long);
        assert_eq!(normalized.len(), MAX_NAME_LEN);
    }

    #[test]
    fn dedupe_appends_numeric_suffix() {
        let taken: HashSet<String> = ["host-a".to_string()].into();
        let name = NodeName::dedupe("host-a", |n| taken.contains(n)).unwrap();
        assert_eq!(name, "host-a-2");
    }

    #[test]
    fn dedupe_returns_base_when_free() {
        let name = NodeName::dedupe("host-a", |_| false).unwrap();
        assert_eq!(name, "host-a");
    }

    #[test]
    fn dedupe_gives_up_after_99() {
        let taken: HashSet<String> = {
            let mut set = HashSet::new();
            set.insert("host-a".to_string());
            for n in 2..=MAX_SUFFIX {
                set.insert(format!("host-a-{n}"));
            }
            set
        };
        assert!(NodeName::dedupe("host-a", |n| taken.contains(n)).is_none());
    }
}
