-- #71 / OB-1：Node 随 Hello 上报的软件版本与平台；last_seen 由 coord 批量落库。
-- 全部可空：旧 Node（< 0.3）不带这些字段，保持 NULL，界面显示「未知（< 0.3）」。
ALTER TABLE nodes ADD COLUMN node_version TEXT NULL;
ALTER TABLE nodes ADD COLUMN os TEXT NULL;
ALTER TABLE nodes ADD COLUMN arch TEXT NULL;
ALTER TABLE nodes ADD COLUMN last_seen_unix INTEGER NULL;
