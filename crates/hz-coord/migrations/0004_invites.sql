-- 邀请码（#55）：只存 sha256（与 Auth Key 同策略）。normalized 码为去掉
-- "HZ-" 前缀与连字符后的大写串；明文仅在 create 时返回一次。
CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    max_uses INTEGER NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    tags TEXT NOT NULL DEFAULT '[]',
    owner_name TEXT,
    node_ttl_days INTEGER,
    created_by TEXT NOT NULL,
    last_used_at_unix INTEGER,
    revoked_at_unix INTEGER
);
