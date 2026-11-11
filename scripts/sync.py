#!/usr/bin/env python3
"""下载上游路由规则，校验通过后交给工作流发布到本仓库的 Release。

校验内容：
  1. 上游提供的 sha256 校验和
  2. 文件能解析，App 用到的分类都在，条数在合理范围
  3. 抽查固定的 IP 和域名（国内的必须在国内列表里，国外的必须不在）
  4. 和本仓库上一次发布的版本比，变化量不能太大
  5. 用 Xray 实际加载一遍（和 App 相同的分类）

任何一项不通过就以非零状态退出，不发布。只用标准库。
"""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.environ.get("GITHUB_REPOSITORY", "soysuuu-png/available-routing-rules")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
# 只同步发布满这么多小时的上游版本，给社区留出发现问题的时间
MIN_AGE_HOURS = float(os.environ.get("MIN_AGE_HOURS", "48"))
# 和上一次发布相比，允许的最大变化比例
MAX_CHANGE = float(os.environ.get("MAX_CHANGE", "0.10"))
XRAY_BIN = os.environ.get("XRAY_BIN", "")
REQUIRE_XRAY = os.environ.get("REQUIRE_XRAY", "") == "1"
OUT_DIR = os.environ.get("OUT_DIR", "out")

SOURCES = {
    "geosite": {"repo": "v2fly/domain-list-community", "asset": "dlc.dat"},
    "geoip": {"repo": "v2fly/geoip", "asset": "geoip-only-cn-private.dat"},
}

# 抽查用的固定地址
CN_IPS = ["223.5.5.5", "114.114.114.114", "180.76.76.76", "1.12.12.12", "39.156.66.10", "101.226.4.6"]
NOT_CN_IPS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "149.154.167.50",
              "142.250.72.14", "104.16.132.229", "140.82.112.3", "157.240.1.35"]
PRIVATE_IPS = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
CN_DOMAINS = ["baidu.com", "www.qq.com", "taobao.com", "douyin.com", "bilibili.com", "weibo.com"]
NOT_CN_DOMAINS = ["google.com", "www.youtube.com", "facebook.com", "x.com", "twitter.com",
                  "telegram.org", "github.com", "instagram.com", "wikipedia.org", "openai.com"]
GOOGLE_DOMAINS = ["google.com", "www.youtube.com", "gstatic.com"]


class CheckFailed(Exception):
    pass


def check(ok, message):
    if not ok:
        raise CheckFailed(message)
    print(f"  ✓ {message}")


# ---------- 网络 ----------

def http_get(url, accept=None):
    req = urllib.request.Request(url, headers={"User-Agent": "routing-rules-sync"})
    if accept:
        req.add_header("Accept", accept)
    if TOKEN and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {TOKEN}")
    # 网络抖动时重试；HTTP 状态码错误（比如 404）不重试，直接交给调用方
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, OSError) as e:
            if attempt == 3:
                raise
            print(f"  - 请求失败，重试（{e}）")
            time.sleep(3 * (attempt + 1))


def api(path):
    return json.loads(http_get(f"https://api.github.com/{path}", "application/vnd.github+json"))


def pick_release(repo, asset):
    """最新的、发布时间满 MIN_AGE_HOURS 且带有所需文件的上游版本"""
    now = datetime.datetime.now(datetime.timezone.utc)
    for rel in api(f"repos/{repo}/releases?per_page=50"):
        if rel.get("draft") or rel.get("prerelease"):
            continue
        published = datetime.datetime.fromisoformat(rel["published_at"].replace("Z", "+00:00"))
        age = (now - published).total_seconds() / 3600
        assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
        if age >= MIN_AGE_HOURS and asset in assets:
            return rel["tag_name"], assets, age
    raise CheckFailed(f"{repo} 没有发布满 {MIN_AGE_HOURS:g} 小时且包含 {asset} 的版本")


# ---------- protobuf（只需要变长整数和带长度的字段） ----------

def read_varint(buf, i):
    result = shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise CheckFailed("protobuf 变长整数过长，文件已损坏")


def fields(buf):
    i, n = 0, len(buf)
    while i < n:
        key, i = read_varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = read_varint(buf, i)
        elif wire == 2:
            length, i = read_varint(buf, i)
            if i + length > n:
                raise CheckFailed("protobuf 字段长度越界，文件已损坏")
            value = buf[i:i + length]
            i += length
        elif wire == 1:
            value, i = buf[i:i + 8], i + 8
        elif wire == 5:
            value, i = buf[i:i + 4], i + 4
        else:
            raise CheckFailed(f"protobuf 出现不认识的字段类型 {wire}，文件已损坏")
        yield field, value


def parse_geoip(data):
    """{分类: {"v4": [网段], "v6": 数量}}"""
    result = {}
    view = memoryview(data)
    for field, entry in fields(view):
        if field != 1:
            continue
        code, v4, v6 = "", [], 0
        for f, value in fields(entry):
            if f == 1:
                code = bytes(value).decode()
            elif f == 2:
                ip, prefix = b"", 0
                for g, x in fields(value):
                    if g == 1:
                        ip = bytes(x)
                    elif g == 2:
                        prefix = x
                if len(ip) == 4:
                    v4.append(ipaddress.ip_network((ip, prefix), strict=False))
                elif len(ip) == 16:
                    v6 += 1
                else:
                    raise CheckFailed(f"geoip {code} 里有长度不对的 IP")
        result[code.upper()] = {"v4": v4, "v6": v6}
    return result


def parse_geosite(data):
    """{分类: [(类型, 值)]}，类型 0=关键字 1=正则 2=域名及子域名 3=完整匹配"""
    result = {}
    view = memoryview(data)
    for field, entry in fields(view):
        if field != 1:
            continue
        code, domains = "", []
        for f, value in fields(entry):
            if f == 1:
                code = bytes(value).decode()
            elif f == 2:
                kind, text = 0, ""
                for g, x in fields(value):
                    if g == 1:
                        kind = x
                    elif g == 2:
                        text = bytes(x).decode()
                domains.append((kind, text))
        result[code.upper()] = domains
    return result


class DomainSet:
    def __init__(self, domains):
        self.root = {v.lower() for k, v in domains if k == 2}
        self.full = {v.lower() for k, v in domains if k == 3}
        self.plain = [v.lower() for k, v in domains if k == 0]
        self.regex = [re.compile(v) for k, v in domains if k == 1]

    def match(self, domain):
        domain = domain.lower()
        if domain in self.full:
            return True
        parts = domain.split(".")
        if any(".".join(parts[i:]) in self.root for i in range(len(parts))):
            return True
        return any(p in domain for p in self.plain) or any(r.search(domain) for r in self.regex)


def in_networks(ip, networks):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks)


# ---------- 校验 ----------

def summarize(geoip, geosite, sizes):
    cn = geoip["CN"]["v4"]
    return {
        "geoip_size": sizes["geoip"],
        "geosite_size": sizes["geosite"],
        "cn_ipv4_ranges": len(cn),
        "cn_ipv4_addresses": sum(n.num_addresses for n in cn),
        "cn_domains": len(geosite["CN"]),
        "google_domains": len(geosite["GOOGLE"]),
        "geosite_categories": len(geosite),
    }


def validate(geoip, geosite):
    print("geoip：")
    check("CN" in geoip and "PRIVATE" in geoip, "包含 cn 和 private 两个分类")
    cn = geoip["CN"]["v4"]
    check(4000 <= len(cn) <= 20000, f"国内 IPv4 段数量合理（{len(cn)}）")
    total = sum(n.num_addresses for n in cn)
    check(250e6 <= total <= 450e6, f"国内 IPv4 地址总数合理（{total / 1e6:.0f} 百万）")
    # App 会把这些网段直接排除出隧道，前缀太短的网段会让大片地址绕过 VPN
    shortest = min(n.prefixlen for n in cn)
    check(shortest >= 8, f"国内网段最短前缀 /{shortest}，没有过大的网段")
    for ip in CN_IPS:
        check(in_networks(ip, cn), f"{ip} 在国内列表里")
    for ip in NOT_CN_IPS:
        check(not in_networks(ip, cn), f"{ip} 不在国内列表里")
    private = geoip["PRIVATE"]["v4"]
    for ip in PRIVATE_IPS:
        check(in_networks(ip, private), f"{ip} 在局域网列表里")
    for ip in CN_IPS + NOT_CN_IPS:
        check(not in_networks(ip, private), f"{ip} 不在局域网列表里")

    print("geosite：")
    for code in ("CN", "GOOGLE", "PRIVATE"):
        check(code in geosite and geosite[code], f"包含 {code.lower()} 分类")
    check(len(geosite) >= 500, f"分类数量合理（{len(geosite)}）")
    check(3000 <= len(geosite["CN"]) <= 100000, f"国内域名数量合理（{len(geosite['CN'])}）")
    cn_set = DomainSet(geosite["CN"])
    for d in CN_DOMAINS:
        check(cn_set.match(d), f"{d} 在国内列表里")
    for d in NOT_CN_DOMAINS:
        check(not cn_set.match(d), f"{d} 不在国内列表里")
    google = DomainSet(geosite["GOOGLE"])
    for d in GOOGLE_DOMAINS:
        check(google.match(d), f"{d} 在 google 列表里")
    for d in CN_DOMAINS:
        check(not google.match(d), f"{d} 不在 google 列表里")


def compare(new, old):
    print("和上一次发布对比：")
    for key, value in new.items():
        before = old.get(key)
        if not before:
            continue
        change = abs(value - before) / before
        check(change <= MAX_CHANGE, f"{key}: {before} → {value}（变化 {change:.1%}）")


def xray_test(geoip_path, geosite_path, workdir):
    print("Xray 加载测试：")
    if not XRAY_BIN:
        if REQUIRE_XRAY:
            raise CheckFailed("没有设置 XRAY_BIN，无法做加载测试")
        print("  - 没有设置 XRAY_BIN，跳过")
        return
    assets = os.path.join(workdir, "assets")
    os.makedirs(assets, exist_ok=True)
    for src, name in ((geoip_path, "geoip.dat"), (geosite_path, "geosite.dat")):
        with open(src, "rb") as a, open(os.path.join(assets, name), "wb") as b:
            b.write(a.read())
    # 和 App 里用到的分类保持一致
    config = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": [
            "1.1.1.1",
            {"address": "1.1.1.1", "domains": ["geosite:google"]},
            {"address": "223.5.5.5", "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"]},
        ]},
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "tag": "socks"}],
        "outbounds": [
            {"protocol": "freedom", "tag": "proxy"},
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "domain": ["geosite:google"], "outboundTag": "proxy"},
            {"type": "field", "domain": ["geosite:private", "geosite:cn"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:private", "geoip:cn"], "outboundTag": "direct"},
        ]},
    }
    config_path = os.path.join(workdir, "xray-test.json")
    with open(config_path, "w") as f:
        json.dump(config, f)
    env = dict(os.environ, XRAY_LOCATION_ASSET=assets)
    proc = subprocess.run([XRAY_BIN, "run", "-test", "-config", config_path],
                          env=env, capture_output=True, text=True, timeout=180)
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        raise CheckFailed(f"Xray 加载失败：\n{output}")
    check(True, "Xray 能加载这两个文件")


# ---------- 主流程 ----------

def set_output(**values):
    path = os.environ.get("GITHUB_OUTPUT")
    lines = [f"{k}={v}" for k, v in values.items()]
    if path:
        with open(path, "a") as f:
            f.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    picked = {}
    for key, src in SOURCES.items():
        tag, assets, age = pick_release(src["repo"], src["asset"])
        picked[key] = (tag, assets)
        print(f"{src['repo']}：选用 {tag}（发布于 {age:.0f} 小时前）")

    tag = f"dlc-{picked['geosite'][0]}_geoip-{picked['geoip'][0]}"
    try:
        api(f"repos/{REPO}/releases/tags/{tag}")
        print(f"{tag} 已经发布过，无需更新")
        set_output(publish="false", tag=tag)
        return
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    paths, sizes = {}, {}
    for key, src in SOURCES.items():
        _, assets = picked[key]
        data = http_get(assets[src["asset"]])
        print(f"{src['asset']}：")
        sum_name = src["asset"] + ".sha256sum"
        check(sum_name in assets, "上游提供了 sha256 校验和")
        expected = http_get(assets[sum_name]).decode().split()[0].lower()
        check(hashlib.sha256(data).hexdigest() == expected, "sha256 校验和一致")
        paths[key] = os.path.join(OUT_DIR, src["asset"])
        with open(paths[key], "wb") as f:
            f.write(data)
        sizes[key] = len(data)

    geoip = parse_geoip(open(paths["geoip"], "rb").read())
    geosite = parse_geosite(open(paths["geosite"], "rb").read())
    validate(geoip, geosite)
    summary = summarize(geoip, geosite, sizes)

    try:
        old = json.loads(http_get(f"https://github.com/{REPO}/releases/latest/download/summary.json"))
        compare(summary, old)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        print("和上一次发布对比：\n  - 还没有发布过，跳过")

    xray_test(paths["geoip"], paths["geosite"], OUT_DIR)

    summary["upstream"] = {k: picked[k][0] for k in picked}
    with open(os.path.join(OUT_DIR, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"全部校验通过，待发布版本：{tag}")
    set_output(publish="true", tag=tag)


if __name__ == "__main__":
    try:
        main()
    except CheckFailed as e:
        print(f"\n✗ 校验未通过，不发布：{e}", file=sys.stderr)
        sys.exit(1)
