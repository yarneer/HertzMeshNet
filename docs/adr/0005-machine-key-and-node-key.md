# Node 使用 Machine Key 与 Node Key 两把密钥

Node 的身份由长期不变的 Machine Key 承载，数据面的 WireGuard 密钥（Node Key）独立存在并定期轮换。User 名下的 Node 每 90 天需重新登录；若只用一把密钥，每次轮换都会产生一个新 Node 并改变 Node Address。拆成两把后，重新登录只轮换 Node Key，Node 的身份、Node Address 与 Node Name 保持不变。
