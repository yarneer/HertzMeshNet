CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    machine_key_pub BLOB UNIQUE NOT NULL,
    node_key_pub BLOB NOT NULL,
    name TEXT UNIQUE NOT NULL,
    ipv4 TEXT UNIQUE NOT NULL,
    ipv6 TEXT UNIQUE NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    user_id TEXT NULL REFERENCES users(id),
    expires_at_unix INTEGER NULL,
    revoked_at_unix INTEGER NULL,
    created_at_unix INTEGER NOT NULL
);

CREATE TABLE auth_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT UNIQUE NOT NULL,
    created_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    single_use INTEGER NOT NULL,
    used_at_unix INTEGER NULL,
    tags TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
