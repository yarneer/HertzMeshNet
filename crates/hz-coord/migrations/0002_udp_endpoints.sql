-- Node 的 UDP Endpoint 列表（JSON 数组，元素为 "ip:port"）。
-- StreamNetworkMap 打开时由 Node 上报并整体覆盖。
ALTER TABLE nodes ADD COLUMN udp_endpoints TEXT NOT NULL DEFAULT '[]';
