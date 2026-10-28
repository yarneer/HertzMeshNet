(function () {
  var links = document.querySelectorAll("nav a");
  var who = document.getElementById("who");
  var askDialog = document.getElementById("ask");
  var askText = document.getElementById("ask-text");
  var askInput = document.getElementById("ask-input");
  var nodesMsg = document.getElementById("nodes-msg");
  var keysMsg = document.getElementById("keys-msg");
  var opsMsg = document.getElementById("ops-msg");
  var policyMsg = document.getElementById("policy-msg");
  var nodesBusy = false;
  var nodeRows = {};

  function mark() {
    var hash = location.hash || "#nodes";
    for (var i = 0; i < links.length; i++) {
      if (links[i].getAttribute("href") === hash) {
        links[i].setAttribute("aria-current", "page");
      } else {
        links[i].removeAttribute("aria-current");
      }
    }
  }

  window.addEventListener("hashchange", mark);
  mark();

  function el(tag, text) {
    var node = document.createElement(tag);
    if (text != null) node.textContent = String(text);
    return node;
  }

  function setMsg(node, text, kind) {
    node.textContent = text || "";
    if (kind) node.setAttribute("data-kind", kind);
    else node.removeAttribute("data-kind");
  }

  function api(path, options) {
    var init = { credentials: "same-origin", headers: {} };
    if (options && options.method) init.method = options.method;
    if (options && options.body != null) {
      init.body = options.body;
      init.headers["content-type"] = "application/json";
    }
    return fetch(path, init).then(function (response) {
      if (response.status === 401) {
        location.assign("/admin/login");
        return new Promise(function () {});
      }
      return response.text().then(function (text) {
        var body = {};
        if (text) {
          try {
            body = JSON.parse(text);
          } catch (e) {
            body = {};
          }
        }
        if (!response.ok) {
          var error = new Error(body.message || "请求失败（" + response.status + "）");
          error.status = response.status;
          throw error;
        }
        return body;
      });
    });
  }

  function ask(text, preset) {
    askText.textContent = text;
    if (preset == null) {
      askInput.hidden = true;
      askInput.required = false;
      askInput.value = "";
    } else {
      askInput.hidden = false;
      askInput.required = true;
      askInput.value = preset;
    }
    askDialog.showModal();
    return new Promise(function (resolve) {
      function onClose() {
        askDialog.removeEventListener("close", onClose);
        if (askDialog.returnValue !== "ok") resolve(null);
        else resolve(askInput.hidden ? true : askInput.value);
      }
      askDialog.addEventListener("close", onClose);
    });
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      var ok = document.execCommand("copy");
      area.remove();
      if (ok) resolve();
      else reject();
    });
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-copy]");
    if (!button) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source) return;
    var text = source.textContent;
    if (!text) return;
    var label = button.textContent;
    copyText(text).then(
      function () {
        button.textContent = "已复制";
        setTimeout(function () {
          button.textContent = label;
        }, 1500);
      },
      function () {
        button.textContent = "复制失败";
        setTimeout(function () {
          button.textContent = label;
        }, 1500);
      }
    );
  });

  function time(unix) {
    if (unix == null) return "—";
    var date = new Date(Number(unix) * 1000);
    if (isNaN(date.getTime())) return "—";
    return date.toLocaleString("zh-CN", { hour12: false });
  }

  function age(secs) {
    if (secs == null) return "—";
    var n = Number(secs);
    if (n < 60) return n + " 秒前";
    if (n < 3600) return Math.floor(n / 60) + " 分钟前";
    if (n < 86400) return Math.floor(n / 3600) + " 小时前";
    return Math.floor(n / 86400) + " 天前";
  }

  function fillDl(id, rows) {
    var dl = document.getElementById(id);
    dl.textContent = "";
    rows.forEach(function (row) {
      dl.appendChild(el("dt", row[0]));
      dl.appendChild(el("dd", row[1]));
    });
  }

  function nodeUrl(id, suffix) {
    return "/admin/api/nodes/" + encodeURIComponent(id) + (suffix || "");
  }

  var RUNBOOK = "https://github.com/yarneer/HertzMeshNet/blob/dev/docs/runbook.md";

  var REASON_TEXT = {
    local_udp_broken: "本机 IPv4/IPv6 UDP 外发均失败",
    no_candidates: "对端没有可用候选 Endpoint（对端 hzd 过旧或 STUN 失败）",
    handshake_timeout: "打洞信令已往来，但 WireGuard 握手超时（常见：对端安全组未放行 UDP 端口）",
    punch_pending: "打洞进行中，尚无结论",
  };

  var REASON_LINK = {
    local_udp_broken: "#11-故障排查",
    no_candidates: "#11-故障排查",
    handshake_timeout: "#62-云主机自身作为-node",
  };

  function reasonRow(peer, byId) {
    var name = (byId[peer.node_id] && byId[peer.node_id].name) || peer.node_id;
    var text = REASON_TEXT[peer.reason] || peer.reason;
    var anchor = REASON_LINK[peer.reason];
    var link = anchor
      ? ' <a href="' + RUNBOOK + anchor + '" target="_blank" rel="noopener">runbook</a>'
      : "";
    return name + "：" + text + link;
  }

  function versionCell(node) {
    if (!node.version) return "未知（< 0.3）";
    var marks = { same: "", behind: "（落后）", at_min: "（协议到下限）", ahead: "（高于服务端）", unknown: "" };
    return node.version + (marks[node.version_status] || "");
  }

  function platform(node) {
    if (!node.os && !node.arch) return "—";
    return [node.os, node.arch].filter(Boolean).join("/");
  }

  function dotTitle(health) {
    var head = { red: "异常", yellow: "注意", blue: "版本高于服务端", green: "正常", gray: "无数据" }[
      health.color
    ];
    var reasons = (health.reasons || []).join("；");
    return reasons ? head + "：" + reasons : head;
  }

  function pathSummary(health) {
    if (health.direct_peers == null && !(health.relayed_peers || []).length) return "—";
    var relayed = (health.relayed_peers || []).length;
    return health.direct_peers + " 直连 / " + relayed + " 中转";
  }

  function detailRow(node, byId, columns) {
    var tr = el("tr", null);
    tr.className = "detail";
    var td = el("td", null);
    td.colSpan = columns;
    var health = node.health || {};
    var title = el("p", "netcheck 摘要");
    title.className = "detail-title";
    td.appendChild(title);
    var mark = function (ok) {
      return ok ? "正常" : "异常";
    };
    if (health.udp4_ok == null) {
      td.appendChild(el("p", "等待上报（hzd < 0.3 或刚启动）"));
    } else {
      fillDlInto(td, [
        ["IPv4 UDP", mark(health.udp4_ok)],
        ["IPv6 UDP", mark(health.udp6_ok)],
        ["公网 STUN 映射", mark(health.has_stun_mapping)],
        [
          "NAT",
          health.nat === "hard"
            ? "hard（端点相关，与 hard NAT 对端无法直连）"
            : health.nat === "easy"
              ? "easy（端点无关）"
              : "unknown（目标不足两个）",
        ],
        ["默认路由", health.default_route_virtual ? "虚拟网卡持有（第三方 TUN 工具）" : "物理网卡"],
        ["可疑 Endpoint", health.suspicious_endpoint ? "有（198.18.0.0/15 或回环）" : "无"],
      ]);
      var peersTitle = el("p", "Relayed 对端");
      peersTitle.className = "detail-title";
      td.appendChild(peersTitle);
      var relayed = health.relayed_peers || [];
      if (!relayed.length) {
        td.appendChild(el("p", "无"));
      } else {
        var list = el("ul");
        relayed.forEach(function (peer) {
          var li = el("li");
          // reasonRow 返回的链接是固定文案（REASON_TEXT/REASON_LINK 常量），
          // Node Name 来自 /admin/api/nodes，不含用户可控 HTML。
          li.innerHTML = reasonRow(peer, byId);
          list.appendChild(li);
        });
        td.appendChild(list);
      }
    }
    tr.appendChild(td);
    return tr;
  }

  function fillDlInto(target, rows) {
    var dl = el("dl");
    dl.className = "detail-dl";
    rows.forEach(function (row) {
      dl.appendChild(el("dt", row[0]));
      dl.appendChild(el("dd", row[1]));
    });
    target.appendChild(dl);
  }

  var NODE_COLUMNS = [
    "名称",
    "状态",
    "地址",
    "版本",
    "平台",
    "最后在线",
    "路径",
    "健康",
    "Tag",
    "归属",
    "创建",
    "Node ID",
    "",
  ];

  function renderNodes(nodes) {
    var wrap = document.getElementById("nodes-table");
    wrap.textContent = "";
    nodeRows = {};
    if (!nodes.length) {
      wrap.appendChild(el("p", "还没有 Node。"));
      return;
    }
    var byId = {};
    nodes.forEach(function (node) {
      byId[node.node_id] = node;
    });
    var table = el("table");
    var head = el("tr");
    NODE_COLUMNS.forEach(function (label) {
      head.appendChild(el("th", label));
    });
    table.appendChild(head);
    nodes.forEach(function (node) {
      nodeRows[node.node_id] = node;
      var row = el("tr");
      if (node.revoked) row.className = "revoked";
      row.setAttribute("data-node", node.node_id);
      var name = el("td", node.name);
      name.className = "node-name";
      row.appendChild(name);
      var state = node.online ? "在线" : "离线";
      if (node.revoked) state += " · 已吊销 " + time(node.revoked_at_unix);
      if (node.expires_at_unix) state += " · 到期 " + time(node.expires_at_unix);
      row.appendChild(el("td", state));
      row.appendChild(el("td", [node.ipv4, node.ipv6].filter(Boolean).join(" / ") || "—"));
      row.appendChild(el("td", versionCell(node)));
      row.appendChild(el("td", platform(node)));
      row.appendChild(el("td", node.last_seen_unix ? age(nowUnix() - node.last_seen_unix) : "—"));
      row.appendChild(el("td", node.health ? pathSummary(node.health) : "—"));
      var dotCell = el("td", null);
      var dot = el("span", null);
      dot.className = "dot dot-" + ((node.health && node.health.color) || "gray");
      if (node.health) dot.title = dotTitle(node.health);
      dotCell.appendChild(dot);
      row.appendChild(dotCell);
      row.appendChild(el("td", node.tags && node.tags.length ? node.tags.join(", ") : "无"));
      row.appendChild(el("td", node.owner_user || "无（Tag 注册）"));
      row.appendChild(el("td", time(node.created_at_unix)));
      row.appendChild(el("td", node.node_id));
      var actions = el("td");
      actions.className = "row-actions";
      actions.appendChild(actionButton("改名", "rename", node.node_id));
      if (!node.revoked) actions.appendChild(actionButton("吊销", "revoke", node.node_id));
      actions.appendChild(actionButton("删除", "delete", node.node_id));
      row.appendChild(actions);
      table.appendChild(row);
      var detail = detailRow(node, byId, NODE_COLUMNS.length);
      detail.setAttribute("data-detail", node.node_id);
      detail.hidden = true;
      table.appendChild(detail);
    });
    table.addEventListener("click", onNodeClick);
    wrap.appendChild(table);
  }

  function nowUnix() {
    return Math.floor(Date.now() / 1000);
  }

  function actionButton(label, act, id) {
    var node = el("button", label);
    node.type = "button";
    node.setAttribute("data-act", act);
    node.setAttribute("data-id", id);
    return node;
  }

  function loadNodes() {
    return api("/admin/api/nodes").then(function (body) {
      renderNodes(body.nodes || []);
    });
  }

  function withNodes(work) {
    if (nodesBusy) return;
    nodesBusy = true;
    Promise.resolve()
      .then(work)
      .then(function (message) {
        if (!message) return;
        return loadNodes().then(function () {
          setMsg(nodesMsg, message, "ok");
        });
      })
      .catch(function (error) {
        if (error && error.message) setMsg(nodesMsg, error.message, "err");
      })
      .then(function () {
        nodesBusy = false;
      });
  }

  function onNodeClick(event) {
    // 点名称单元格（或行内非按钮区域）展开 / 收起节点详情（#73）。
    var mainRow = event.target.closest("tr[data-node]");
    if (mainRow && !event.target.closest("button")) {
      var detail = document.querySelector('tr[data-detail="' + mainRow.getAttribute("data-node") + '"]');
      if (detail) detail.hidden = !detail.hidden;
      return;
    }
    var button = event.target.closest("button[data-act]");
    if (!button) return;
    var node = nodeRows[button.getAttribute("data-id")];
    if (!node) return;
    var act = button.getAttribute("data-act");
    if (act === "rename") {
      withNodes(function () {
        return ask("确认把「" + node.name + "」改成下面的名称？名称会规范成小写。", node.name).then(
          function (value) {
            if (value == null) return;
            var name = String(value).trim();
            if (!name || name === node.name) return;
            return api(nodeUrl(node.node_id, "/rename"), {
              method: "POST",
              body: JSON.stringify({ name: name }),
            }).then(function (body) {
              return "已改名为 " + body.name + "。";
            });
          }
        );
      });
      return;
    }
    if (act === "revoke") {
      withNodes(function () {
        return ask(
          "确认吊销 Node「" + node.name + "」（" + node.node_id + "）？记录会保留，该 Node 不能再接入。"
        ).then(function (ok) {
          if (ok !== true) return;
          return api(nodeUrl(node.node_id, "/revoke"), { method: "POST" }).then(function () {
            return "已吊销 " + node.name + "，记录仍在。";
          });
        });
      });
      return;
    }
    if (act === "delete") {
      withNodes(function () {
        return ask(
          "确认永久删除 Node「" + node.name + "」（" + node.node_id + "）？删除后无法恢复。"
        ).then(function (ok) {
          if (ok !== true) return;
          return api(nodeUrl(node.node_id), { method: "DELETE" }).then(function () {
            return "已删除 " + node.name + "。";
          });
        });
      });
    }
  }

  function pad(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function toLocalInput(date) {
    return (
      date.getFullYear() +
      "-" +
      pad(date.getMonth() + 1) +
      "-" +
      pad(date.getDate()) +
      "T" +
      pad(date.getHours()) +
      ":" +
      pad(date.getMinutes())
    );
  }

  var keyForm = document.getElementById("key-create");
  keyForm.expires.value = toLocalInput(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));

  function clearKeyOnce() {
    document.getElementById("key-plain").textContent = "";
    document.getElementById("key-id").textContent = "";
    document.getElementById("key-once").hidden = true;
  }

  document.getElementById("key-dismiss").addEventListener("click", clearKeyOnce);

  keyForm.addEventListener("submit", function (event) {
    event.preventDefault();
    var submit = keyForm.querySelector("button[type=submit]");
    if (submit.disabled) return;
    var when = new Date(keyForm.expires.value);
    if (isNaN(when.getTime()) || when.getTime() <= Date.now()) {
      setMsg(keysMsg, "到期时间必须在未来。", "err");
      return;
    }
    var tags = String(keyForm.tags.value)
      .split(/[\s,，]+/)
      .filter(function (tag) {
        return tag.length > 0;
      });
    if (!tags.length) {
      setMsg(keysMsg, "至少填写一个 Tag。", "err");
      return;
    }
    submit.disabled = true;
    setMsg(keysMsg, "正在签发…", "");
    api("/admin/api/auth-keys", {
      method: "POST",
      body: JSON.stringify({
        expires_unix: Math.floor(when.getTime() / 1000),
        single_use: keyForm.single_use.checked,
        tags: tags,
      }),
    })
      .then(function (body) {
        document.getElementById("key-id").textContent = body.key_id || "";
        document.getElementById("key-plain").textContent = body.auth_key || "";
        document.getElementById("key-once").hidden = false;
        setMsg(keysMsg, "已签发。请立即复制明文与 Key ID，本页没有清单。", "ok");
      })
      .catch(function (error) {
        setMsg(keysMsg, error.message, "err");
      })
      .then(function () {
        submit.disabled = false;
      });
  });

  document.getElementById("key-revoke").addEventListener("submit", function (event) {
    event.preventDefault();
    var keyId = String(document.querySelector("#key-revoke [name=key_id]").value).trim();
    if (!keyId) return;
    ask("确认吊销 Auth Key「" + keyId + "」？").then(function (ok) {
      if (ok !== true) return;
      setMsg(keysMsg, "正在吊销…", "");
      api("/admin/api/auth-keys/" + encodeURIComponent(keyId) + "/revoke", {
        method: "POST",
      }).then(
        function () {
          document.querySelector("#key-revoke [name=key_id]").value = "";
          setMsg(keysMsg, "已吊销该 Key ID。", "ok");
        },
        function (error) {
          setMsg(keysMsg, error.message, "err");
        }
      );
    });
  });

  function certLabel(status) {
    return (
      {
        ok: "正常",
        expiring: "即将到期",
        expired: "已过期",
        missing: "缺失",
        unreadable: "无法读取",
      }[status] || status
    );
  }

  function relayText(relay) {
    if (!relay) return "未采集";
    var pct = Math.round(Number(relay.punch_success_ratio) * 1000) / 10;
    return (
      "成功 " +
      relay.punch_success_total +
      " / 尝试 " +
      relay.punch_attempts_total +
      "（" +
      pct +
      "%）"
    );
  }

  function backupRows(backup) {
    var fresh = "还没有备份";
    if (!backup.readable) fresh = "目录不可读";
    else if (backup.count > 0) fresh = backup.fresh ? "新鲜" : "过旧";
    var hours = Math.round(Number(backup.fresh_within_secs) / 3600);
    return [
      ["目录", backup.dir || "—"],
      ["可读", backup.readable ? "是" : "否"],
      ["份数", String(backup.count)],
      ["最新", backup.latest || "—"],
      ["最新时间", time(backup.latest_unix)],
      ["年龄", age(backup.age_secs)],
      ["新旧", fresh + "（" + hours + " 小时内算新鲜）"],
    ];
  }

  function renderCerts(certs) {
    var wrap = document.getElementById("ops-certs");
    wrap.textContent = "";
    if (!certs || !certs.length) {
      wrap.appendChild(el("p", "没有证书状态。"));
      return;
    }
    var table = el("table");
    var head = el("tr");
    ["证书", "状态", "到期", "路径"].forEach(function (label) {
      head.appendChild(el("th", label));
    });
    table.appendChild(head);
    certs.forEach(function (cert) {
      var row = el("tr");
      row.appendChild(el("td", cert.name));
      var status = el("td", certLabel(cert.status));
      status.setAttribute("data-status", cert.status || "");
      row.appendChild(status);
      row.appendChild(el("td", cert.not_after || time(cert.not_after_unix)));
      row.appendChild(el("td", cert.path || "—"));
      table.appendChild(row);
    });
    wrap.appendChild(table);
  }

  function loadHealth() {
    return api("/admin/api/health").then(function (body) {
      fillDl("ops-health", [
        ["healthz", body.healthz === "ok" ? "正常" : body.healthz],
        [
          "Node",
          "在线 " +
            body.online_nodes +
            " / 共 " +
            body.nodes +
            "（已吊销 " +
            body.revoked_nodes +
            "）",
        ],
        ["打洞", relayText(body.relay)],
      ]);
    });
  }

  function loadOps() {
    return api("/admin/api/ops/status").then(function (body) {
      fillDl("ops-backup", backupRows(body.backup || {}));
      renderCerts(body.certs || []);
    });
  }

  function loadOpsPage() {
    setMsg(opsMsg, "", "");
    return Promise.all([
      loadHealth().then(
        function () {
          return "";
        },
        function (error) {
          document.getElementById("ops-health").textContent = "";
          return error.message;
        }
      ),
      loadOps().then(
        function () {
          return "";
        },
        function (error) {
          return error.message;
        }
      ),
    ]).then(function (errors) {
      var text = errors.filter(Boolean).join(" ");
      if (text) setMsg(opsMsg, text, "err");
    });
  }

  var backupBtn = document.getElementById("backup-run");
  backupBtn.addEventListener("click", function () {
    if (backupBtn.disabled) return;
    ask("确认现在触发一次 SQLite 打包备份？同一时间只能跑一个。").then(function (ok) {
      if (ok !== true) return;
      backupBtn.disabled = true;
      backupBtn.textContent = "备份进行中…";
      backupBtn.setAttribute("aria-busy", "true");
      setMsg(opsMsg, "正在备份，请稍候。", "");
      api("/admin/api/ops/backup", { method: "POST" })
        .then(function (body) {
          setMsg(opsMsg, body.message || "备份完成。", "ok");
          return loadOps();
        })
        .catch(function (error) {
          var prefix = "备份失败";
          if (error.status) prefix += "（" + error.status + "）";
          setMsg(opsMsg, prefix + "：" + (error.message || "请稍后重试"), "err");
        })
        .then(function () {
          backupBtn.disabled = false;
          backupBtn.textContent = "立即备份";
          backupBtn.removeAttribute("aria-busy");
        });
    });
  });

  function loadPolicy() {
    return api("/admin/api/policy").then(function (body) {
      var version = body.version || 0;
      document.getElementById("policy-meta").textContent =
        version > 0 ? "当前版本 " + version : "尚未推送 Policy。";
      document.getElementById("policy-body").textContent = body.content || "（无内容）";
      var list = document.getElementById("policy-history");
      list.textContent = "";
      var history = body.history || [];
      if (!history.length) list.appendChild(el("li", "没有历史版本。"));
      history.forEach(function (row) {
        list.appendChild(el("li", "版本 " + row.version + " · " + time(row.created_at_unix)));
      });
      setMsg(policyMsg, "", "");
    });
  }

  function showNodes() {
    setMsg(nodesMsg, "", "");
    return loadNodes().catch(function (error) {
      document.getElementById("nodes-table").textContent = "";
      setMsg(nodesMsg, error.message, "err");
    });
  }

  document.getElementById("nodes-refresh").addEventListener("click", showNodes);
  document.getElementById("ops-refresh").addEventListener("click", function () {
    loadOpsPage();
  });
  function showPolicy() {
    return loadPolicy().catch(function (error) {
      document.getElementById("policy-meta").textContent = "";
      setMsg(policyMsg, error.message, "err");
    });
  }

  document.getElementById("policy-refresh").addEventListener("click", showPolicy);

  api("/admin/api/me")
    .then(function (body) {
      who.textContent = body.username || body.subject || "";
    })
    .catch(function () {
      who.textContent = "未能读取身份";
    });

  showNodes();
  showPolicy();
  loadOpsPage();
})();
