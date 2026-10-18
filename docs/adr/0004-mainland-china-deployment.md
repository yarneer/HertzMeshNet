# 部署在中国大陆云主机，所有服务共用已备案域名的 443 端口

Coordination Server、Relay 与 Kanidm 部署在中国大陆的云主机（阿里云/腾讯云类，带独立公网 IP）上。大陆主机对外提供 HTTPS 服务须使用已备案域名，所以三者都使用已备案域名、通过子域名（`coord.` / `relay.` / `auth.`）共用 TCP 443；STUN 额外开放 UDP 3478。Kanidm 必须可从公网访问，因为 User 首次登录时其设备尚未加入 HzNet。
