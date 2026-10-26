# Admin Console 嵌在 hz-coord 里，由现有 HTTP 面的 /admin/ 提供

Admin Console（给 HzNet Admin 用的浏览器界面）嵌在 `hz-coord` 里，由它现有的 axum HTTP 面在路径前缀 `/admin/` 下提供，例如 `https://coord.<域名>/admin/`。认证走 Kanidm OIDC，只有 `hznet_admins` 的成员可以进入。v1 前端是少量静态 HTML/CSS/JS，不引入 SPA 构建链。v1 不做 User 自助界面、容器或 K8s、在浏览器里修改 Policy（只读可以），也不通过界面重启或升级。

曾考虑单独的 `hz-admin` 二进制、由 nginx 托管的 SPA，以及 Vue/React。这些都会多出一个进程或一条构建链，与大陆单进程部署（[ADR-0004](0004-mainland-china-deployment.md)）和尽量小的表面相悖，因此不采用。
