CREATE TABLE policy_versions (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL
);
