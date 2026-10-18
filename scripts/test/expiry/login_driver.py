#!/usr/bin/env python3
"""无头浏览器驱动 Kanidm 登录（#11 有效期 Docker 门禁的宿主侧组件）。

传输一律用 curl 子进程（与 scripts/test/kanidm/setup.sh 相同的通道，cookie 落
jar 文件）；语义与 crates/hz-coord/tests/kanidm_login.rs 的 drive_browser 一致：
登录表单一律直接 POST（登录后的 GET /ui/login* 会在已认证会话上 303 循环）。

用法：login_driver.py --url <hz up 打印的一次性链接> --issuer <Kanidm issuer> \
        --username alice --password ... --ca chain.pem
退出码：0 = 回调落到 coord 成功页；2 = 流程断言失败。
"""

import argparse
import os
import subprocess
import sys
import tempfile
import urllib.parse

MAX_HOPS = 25


class Browser:
    def __init__(self, ca_path, jar_path):
        self.ca = ca_path
        self.jar = jar_path

    def request(self, method, url, form=None):
        command = ["curl", "-s", "--max-time", "20", "--cacert", self.ca,
                   "-b", self.jar, "-c", self.jar,
                   "-o", self.body_path, "-w", "%{http_code} %{redirect_url}"]
        if method == "POST":
            command += ["-X", "POST", "-H", "Content-Type: application/x-www-form-urlencoded"]
            for key, value in (form or {}).items():
                command += ["--data-urlencode", "%s=%s" % (key, value)]
        command.append(url)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("curl %s 失败（rc=%d）：%s" % (url, result.returncode, result.stderr.strip()))
        code, _, redirect = result.stdout.strip().partition(" ")
        with open(self.body_path, encoding="utf-8", errors="replace") as body:
            page = body.read()
        return int(code), redirect.strip(), page


def form_action(page):
    marker = 'action="'
    if marker not in page:
        return None
    return page.split(marker, 1)[1].split('"', 1)[0]


def hidden_value(page, name):
    after = page.split('name="%s"' % name, 1)[1]
    return after.split('value="', 1)[1].split('"', 1)[0]


def drive(url, issuer, username, password, browser):
    current = url
    step = ("GET", current, None)

    for _ in range(MAX_HOPS):
        if step[0] == "GET":
            code, redirect, page = browser.request("GET", step[1])
        else:
            code, redirect, page = browser.request("POST", step[1], step[2])
        current = step[1]
        print("login_driver: %s %s -> %s%s" % (
            step[0], step[1], code, (" -> " + redirect) if redirect else ""), file=sys.stderr)
        if code >= 400:
            return "请求 %s 返回 %s：%s" % (step[1], code, page[:200])

        if redirect:
            # 与真实浏览器一致：Location 相对当前页面解析。
            target = urllib.parse.urljoin(current, redirect)
            if target.startswith("http://127.0.0.1"):
                code, _, page = browser.request("GET", target)
                if "登录成功" not in page:
                    return "回调页不是登录成功（%s）：%s" % (code, page[:200])
                return None
            step = ("GET", target, None)
            continue

        action = form_action(page)
        if action is None:
            return "页面没有表单：%s" % page[:200]
        target = urllib.parse.urljoin(current, action)
        if action.endswith("/login/begin"):
            step = ("POST", target,
                    {"username": username, "password": password, "remember_me": "1"})
        elif action.endswith("/login/pw"):
            step = ("POST", target, {"password": password})
        elif action.endswith("/oauth2/consent"):
            step = ("POST", target,
                    {"consent_token": hidden_value(page, "consent_token")})
        else:
            return "未知表单 %s" % action
    return "跳数超过 %d" % MAX_HOPS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--ca", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        browser = Browser(args.ca, os.path.join(tmp, "cookies.txt"))
        browser.body_path = os.path.join(tmp, "body.html")
        try:
            error = drive(args.url, args.issuer, args.username, args.password, browser)
        except RuntimeError as runtime_error:
            error = str(runtime_error)
    if error:
        print("login_driver: %s" % error, file=sys.stderr)
        return 2
    print("login_driver: 登录成功")
    return 0


if __name__ == "__main__":
    sys.exit(main())
