#!/usr/bin/env python3
"""
clash2singbox.py — 适配 sing-box 1.12+
主要变化（相对旧版）:
  - DNS servers 改用 type 字段，fakeip 移入 server 定义
  - outbound DNS rule item 废弃，改用 domain_resolver
  - block/dns outbound 废弃，改用 rule action: reject / hijack-dns
  - geoip 废弃，改用 rule_set
  - independent_cache 废弃，直接删除
"""

import yaml, json, sys, re

FINGERPRINT_MAP = {
    "chrome": "chrome", "firefox": "firefox", "safari": "safari",
    "ios": "safari", "edge": "edge", "qq": "chrome",
    "random": "random", "": "chrome",
}

INFO_PAT = re.compile(r"(剩余流量|距离|套餐到期|导航页)", re.UNICODE)

def clean_tag(name):
    return name.strip()

# ── 节点转换 ──────────────────────────────────────────────

def convert_vless(p):
    tag = clean_tag(p["name"])
    out = {
        "type": "vless",
        "tag": tag,
        "server": p["server"],
        "server_port": int(p["port"]),
        "uuid": p["uuid"],
        "packet_encoding": "xudp" if p.get("udp") else "",
    }
    network = p.get("network", "tcp")
    reality_opts = p.get("reality-opts")
    if reality_opts:
        fp = FINGERPRINT_MAP.get(p.get("client-fingerprint", ""), "chrome")
        out["tls"] = {
            "enabled": True,
            "server_name": p.get("servername", p["server"]),
            "utls": {"enabled": True, "fingerprint": fp},
            "reality": {
                "enabled": True,
                "public_key": reality_opts.get("public-key", ""),
                "short_id": reality_opts.get("short-id", ""),
            },
        }
    elif p.get("tls"):
        fp = FINGERPRINT_MAP.get(p.get("client-fingerprint", ""), "chrome")
        tls = {"enabled": True, "server_name": p.get("servername", p["server"])}
        if p.get("client-fingerprint"):
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        out["tls"] = tls

    if network == "ws":
        ws = p.get("ws-opts", {})
        transport = {"type": "ws", "path": ws.get("path", "/")}
        if ws.get("headers"):
            transport["headers"] = ws["headers"]
        out["transport"] = transport
    elif network == "grpc":
        out["transport"] = {
            "type": "grpc",
            "service_name": p.get("grpc-opts", {}).get("grpc-service-name", ""),
        }
    return out

def convert_vmess(p):
    tag = clean_tag(p["name"])
    out = {
        "type": "vmess",
        "tag": tag,
        "server": p["server"],
        "server_port": int(p["port"]),
        "uuid": p["uuid"],
        "alter_id": int(p.get("alterId", 0)),
        "security": p.get("cipher", "auto"),
        "packet_encoding": "xudp" if p.get("udp") else "",
    }
    if p.get("tls"):
        out["tls"] = {"enabled": True, "server_name": p.get("servername", p["server"])}
    if p.get("network") == "ws":
        ws = p.get("ws-opts", {})
        transport = {"type": "ws", "path": ws.get("path", "/")}
        if ws.get("headers"):
            transport["headers"] = ws["headers"]
        out["transport"] = transport
    return out

def convert_ss(p):
    return {
        "type": "shadowsocks",
        "tag": clean_tag(p["name"]),
        "server": p["server"],
        "server_port": int(p["port"]),
        "method": p.get("cipher", "aes-256-gcm"),
        "password": p.get("password", ""),
    }

def convert_trojan(p):
    return {
        "type": "trojan",
        "tag": clean_tag(p["name"]),
        "server": p["server"],
        "server_port": int(p["port"]),
        "password": p.get("password", ""),
        "tls": {
            "enabled": True,
            "server_name": p.get("sni", p.get("servername", p["server"])),
        },
    }

# ── proxy-groups ──────────────────────────────────────────

def convert_groups(groups, proxy_tags):
    result = []
    group_names = {g["name"] for g in groups}
    for g in groups:
        gtype = g.get("type", "select")
        tag = clean_tag(g["name"])
        raw = g.get("proxies", [])
        outbounds = []
        for p in raw:
            pt = clean_tag(p)
            if pt == "DIRECT":
                outbounds.append("direct")
            elif pt == "REJECT":
                pass  # reject 现在是 rule action，不放进 outbounds
            elif pt in proxy_tags or pt in group_names:
                outbounds.append(pt)

        if gtype == "select":
            entry = {
                "type": "selector",
                "tag": tag,
                "outbounds": outbounds,
                "default": outbounds[0] if outbounds else "direct",
            }
        elif gtype in ("url-test", "fallback", "load-balance"):
            entry = {
                "type": "urltest",
                "tag": tag,
                "outbounds": outbounds,
                "url": g.get("url", "https://www.gstatic.com/generate_204"),
                "interval": "3m",
                "idle_timeout": "30m",
                "tolerance": 50,
            }
        else:
            entry = {"type": "selector", "tag": tag, "outbounds": outbounds}
        result.append(entry)
    return result

# ── rules ─────────────────────────────────────────────────

def convert_rules(rules, all_names):
    domain_rules        = {}
    domain_suffix_rules = {}
    ip_cidr_rules       = {}
    geoip_rules         = {}
    other_rules         = []
    final_outbound      = "direct"

    def resolve_ob(name):
        n = name.strip()
        if n in ("DIRECT", "🎯 全球直连"):
            return "direct"
        if n == "REJECT":
            return "reject"
        return clean_tag(n)

    for rule in rules:
        rule = rule.strip()
        parts = [x.strip() for x in rule.split(",")]
        if len(parts) < 2:
            continue
        rtype  = parts[0].upper()
        rvalue = parts[1]
        ob_raw = parts[-1]
        if ob_raw.lower() == "no-resolve":
            ob_raw = parts[-2]
        ob = resolve_ob(ob_raw)

        if rtype == "DOMAIN":
            domain_rules.setdefault(ob, []).append(rvalue)
        elif rtype == "DOMAIN-SUFFIX":
            domain_suffix_rules.setdefault(ob, []).append(rvalue)
        elif rtype in ("IP-CIDR", "IP-CIDR6"):
            ip_cidr_rules.setdefault(ob, []).append(rvalue)
        elif rtype == "GEOIP":
            geoip_rules.setdefault(ob, []).append(rvalue.lower())
        elif rtype == "GEOSITE":
            other_rules.append({"rule_set": [f"geosite-{rvalue.lower()}"], "outbound": ob})
        elif rtype in ("MATCH", "FINAL"):
            final_outbound = ob

    sb_rules = []
    all_obs = set(
        list(domain_rules) + list(domain_suffix_rules) +
        list(ip_cidr_rules) + list(geoip_rules)
    )
    for ob in all_obs:
        entry = {"action": "reject"} if ob == "reject" else {"outbound": ob}
        if ob in domain_rules:
            entry["domain"] = domain_rules[ob]
        if ob in domain_suffix_rules:
            entry["domain_suffix"] = domain_suffix_rules[ob]
        if ob in ip_cidr_rules:
            entry["ip_cidr"] = ip_cidr_rules[ob]
        if ob in geoip_rules:
            entry.setdefault("rule_set", []).extend(
                [f"geoip-{c}" for c in geoip_rules[ob]]
            )
        sb_rules.append(entry)

    sb_rules.extend(other_rules)
    return sb_rules, final_outbound

# ── 主函数 ────────────────────────────────────────────────

def convert(clash_path, output_path):
    with open(clash_path, "r", encoding="utf-8") as f:
        clash = yaml.safe_load(f)

    # 1. 节点
    outbounds  = []
    proxy_tags = set()
    for p in clash.get("proxies", []):
        if INFO_PAT.search(p.get("name", "")):
            continue
        ptype = p.get("type", "").lower()
        node  = None
        if ptype == "vless":                 node = convert_vless(p)
        elif ptype == "vmess":               node = convert_vmess(p)
        elif ptype in ("ss","shadowsocks"):  node = convert_ss(p)
        elif ptype == "trojan":              node = convert_trojan(p)
        if node:
            outbounds.append(node)
            proxy_tags.add(node["tag"])

    # 2. proxy-groups
    groups          = clash.get("proxy-groups", [])
    group_outbounds = convert_groups(groups, proxy_tags)
    group_names     = {g["tag"] for g in group_outbounds}
    all_names       = proxy_tags | group_names
    first_group     = group_outbounds[0]["tag"] if group_outbounds else "direct"

    # 3. rules
    route_rules, final_outbound = convert_rules(clash.get("rules", []), all_names)
    if final_outbound not in all_names and final_outbound not in ("direct", "reject"):
        final_outbound = first_group

    # 4. DNS — 1.12+ 新格式（type 字段 + fakeip 作为独立 server）
    clash_dns    = clash.get("dns", {})
    is_fakeip    = clash_dns.get("enhanced-mode") == "fake-ip"
    fakeip_range = clash_dns.get("fake-ip-range", "198.18.0.0/15")

    dns_servers = [
        {
            "type": "https",
            "tag": "dns-remote",
            "server": "8.8.8.8",
            "detour": first_group,
            "domain_resolver": "dns-local",
        },
        {
            "type": "https",
            "tag": "dns-local",
            "server": "223.5.5.5",
        },
    ]
    dns_rules = [
        {
            "rule_set": ["geosite-cn"],
            "action": "route",
            "server": "dns-local",
        },
    ]
    if is_fakeip:
        dns_servers.append({
            "type": "fakeip",
            "tag": "dns-fakeip",
            "inet4_range": fakeip_range,
        })
        dns_rules.append({
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "dns-fakeip",
        })

    dns_config = {
        "servers": dns_servers,
        "rules": dns_rules,
        "final": "dns-remote",
    }

    # 5. rule_set（1.8+ 替代 geoip/geosite 字段）
    rule_set = [
        {
            "tag": "geoip-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
            "download_detour": first_group,
        },
        {
            "tag": "geosite-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
            "download_detour": first_group,
        },
    ]
    existing_tags = {r["tag"] for r in rule_set}
    for r in route_rules:
        for rs_tag in r.get("rule_set", []):
            if rs_tag not in existing_tags:
                if rs_tag.startswith("geoip-"):
                    code = rs_tag[6:]
                    rule_set.append({
                        "tag": rs_tag, "type": "remote", "format": "binary",
                        "url": f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{code}.srs",
                        "download_detour": first_group,
                    })
                elif rs_tag.startswith("geosite-"):
                    code = rs_tag[8:]
                    rule_set.append({
                        "tag": rs_tag, "type": "remote", "format": "binary",
                        "url": f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{code}.srs",
                        "download_detour": first_group,
                    })
                existing_tags.add(rs_tag)

    # 6. inbounds
    mixed_port = clash.get("mixed-port", 7890)
    clash_tun  = clash.get("tun", {})
    inbounds = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": mixed_port,
        },
        {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000,
            "auto_route": clash_tun.get("auto-route", True),
            "strict_route": True,
            "stack": clash_tun.get("stack", "mixed"),
        },
    ]

    # 7. route 头部规则（1.11+ action 语法）
    head_rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]

    # 8. 组装
    singbox = {
        "log": {
            "level": "warn",
            "output": "box.log",
            "timestamp": True,
        },
        "dns": dns_config,
        "inbounds": inbounds,
        "outbounds": group_outbounds + outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": head_rules + route_rules,
            "rule_set": rule_set,
            "final": final_outbound,
            "auto_detect_interface": True,
            "default_domain_resolver": "dns-local",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": "cache.db",
                "store_fakeip": is_fakeip,
            },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "secret": "",
            },
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(singbox, f, ensure_ascii=False, indent=2)

    print(f"✅ 转换完成: {output_path}")
    print(f"   节点: {len(outbounds)}  策略组: {len(group_outbounds)}  路由规则: {len(route_rules)}  默认出站: {final_outbound}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python3 clash2singbox.py <clash.yaml> <output.json>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
