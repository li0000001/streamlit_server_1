#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 导入所有需要的库
import os
import json
import random
import time
import shutil
import re
import base64
import socket
import ssl
import subprocess
import platform
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlencode, quote, unquote, parse_qsl
import urllib.request
import tarfile
import streamlit as st

# --- 全局常量定义 ---
# 工作目录，所有运行时文件都将存放在这里
INSTALL_DIR = Path.home() / ".agsb"
# 各种运行时文件的具体路径
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "sbargopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
SB_LOG_FILE = INSTALL_DIR / "sb.log"
ALL_NODES_FILE = INSTALL_DIR / "allnodes.txt"
# 运行时配置（面板上改的东西保存到这里），优先级高于 Secrets
CONFIG_FILE = INSTALL_DIR / "config.json"
SB_CONFIG_FILE = INSTALL_DIR / "sb.json"

# 面板可配置项及其默认值。Secrets 与 config.json 只允许覆盖这里出现过的键。
DEFAULT_CONFIG = {
    "uuid_str": "",            # VLESS/Vmess 用户 ID
    "port_vm_ws": 0,           # 本地监听端口，0 = 随机（仅容器内部使用）
    "custom_domain": "",       # 自定义域名，留空走 cloudflared 临时隧道
    "argo_token": "",          # Cloudflare Tunnel Token，留空走临时隧道
    "protocol": "vmess",       # vmess / vless / trojan
    "trojan_password": "",     # 留空则复用 UUID
    "ws_path": "/",            # WebSocket 路径
    "outbound_mode": "direct", # direct = 直连；proxy = 走代理链路
    "hop1": "",                # 一级代理，socks5://user:pass@host:port
    "hop2": "",                # 落地节点，套在一级代理之后
    "preferred_ips": [],       # 优选 IP 列表，每项形如 "1.2.3.4:443#名称"
    "preferred_domain": "",    # 自定义优选域名
}

PROTOCOL_CHOICES = ["vmess", "vless", "trojan"]
MODE_DIRECT = "direct"
MODE_PROXY = "proxy"

# ISO 国家/地区码 → 中文名。用于把数据源里的地区标记翻译成节点名。
REGION_CN = {
    "HK": "香港", "TW": "台湾", "MO": "澳门", "JP": "日本", "SG": "新加坡",
    "US": "美国", "KR": "韩国", "DE": "德国", "FR": "法国", "GB": "英国",
    "CA": "加拿大", "AU": "澳大利亚", "SE": "瑞典", "NL": "荷兰", "FI": "芬兰",
    "NO": "挪威", "DK": "丹麦", "CH": "瑞士", "IT": "意大利", "ES": "西班牙",
    "PT": "葡萄牙", "IE": "爱尔兰", "BE": "比利时", "AT": "奥地利", "PL": "波兰",
    "CZ": "捷克", "RO": "罗马尼亚", "HU": "匈牙利", "GR": "希腊", "RU": "俄罗斯",
    "TR": "土耳其", "UA": "乌克兰", "IN": "印度", "TH": "泰国", "MY": "马来西亚",
    "VN": "越南", "PH": "菲律宾", "ID": "印尼", "BR": "巴西", "MX": "墨西哥",
    "AR": "阿根廷", "CL": "智利", "ZA": "南非", "EG": "埃及", "AE": "阿联酋",
    "IL": "以色列", "NZ": "新西兰", "KZ": "哈萨克斯坦", "SA": "沙特",
}

# 内置地区优选源（社区维护的 bestcf 在线优选池）。
# 这些源下发的每一行都自带地区标记，例如：
#   47.76.171.37:8443#地区随机 | 香港 HK | HKG | 47.76.171.37:8443
# 节点名就是从这里提取出「香港」再编号的 —— 不是靠 IP 反查地理位置。
REGION_SOURCES = [
    ("HK", "香港", "https://bestcf.pages.dev/random-region/HK/100.txt"),
    ("TW", "台湾", "https://bestcf.pages.dev/random-region/TW/100.txt"),
    ("JP", "日本", "https://bestcf.pages.dev/random-region/JP/100.txt"),
    ("SG", "新加坡", "https://bestcf.pages.dev/random-region/SG/100.txt"),
    ("US", "美国", "https://bestcf.pages.dev/random-region/US/100.txt"),
    ("KR", "韩国", "https://bestcf.pages.dev/random-region/KR/100.txt"),
]

# 这些词出现在「|」分段里时不是地区名，是源的固定前缀，要排除掉
REGION_NAME_STOPWORDS = {"地区随机", "随机优选", "官方优选", "优选", "CF优选"}


# --- 辅助函数 ---

def download_file(url, target_path, silent=False):
    """下载文件，可选择是否在界面上显示错误信息。"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        if not silent:
            st.error(f"下载失败: {url}, 错误: {e}")
        return False


def normalize_path(p):
    """把 WebSocket 路径规整成以 / 开头的形式。"""
    p = (p or "/").strip() or "/"
    return p if p.startswith("/") else "/" + p


def parse_proxy_url(raw):
    """解析出站 / 落地地址。

    支持：socks5://user:pass@host:port、http://host:port、host:port，
    以及 IPv6 写法 [::1]:1080。解析失败返回 None。
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    m = re.match(
        r'^(?:(socks5|socks|http|https)://)?'
        r'(?:([^:@/]+):([^@/]*)@)?'
        r'(\[[0-9a-fA-F:]+\]|[^:/@\s]+):(\d{1,5})$',
        raw, re.I)
    if not m:
        return None
    scheme = (m.group(1) or "socks5").lower()
    otype = "http" if scheme in ("http", "https") else "socks"
    port = int(m.group(5))
    if not (0 < port < 65536):
        return None
    return {
        "type": otype,
        "server": m.group(4).strip("[]"),
        "server_port": port,
        "username": m.group(2) or "",
        "password": m.group(3) or "",
    }


def _clean_outbound(parsed, tag, detour=None):
    """把解析结果转成 sing-box 的 outbound 结构，顺手丢掉空字段。"""
    out = {
        "type": parsed["type"],
        "tag": tag,
        "server": parsed["server"],
        "server_port": parsed["server_port"],
    }
    if parsed["type"] == "socks":
        out["version"] = "5"
    if parsed["username"]:
        out["username"] = parsed["username"]
    if parsed["password"]:
        out["password"] = parsed["password"]
    if detour:
        out["detour"] = detour
    return out


def load_runtime_config():
    """读取面板保存的运行时配置，文件不存在或损坏时返回空字典。"""
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_runtime_config(cfg):
    """把配置写入运行时配置文件。"""
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_config(secrets_cfg=None):
    """合并配置。优先级：运行时配置(config.json) > Secrets > 内置默认值。"""
    merged = dict(DEFAULT_CONFIG)
    for src in (secrets_cfg or {}, load_runtime_config()):
        for key, value in src.items():
            if key in DEFAULT_CONFIG and value not in (None, ""):
                merged[key] = value
    return merged


def build_singbox_config(cfg):
    """根据配置生成 sing-box 配置文件内容。

    出站链路顺序：容器 → hop1 → hop2 → 目标。
    hop2 通过 detour 挂到 hop1 后面，实现二级跳。
    """
    port = int(cfg.get("port_vm_ws") or 0)
    ws_path = normalize_path(cfg.get("ws_path"))
    protocol = (cfg.get("protocol") or "vmess").lower()
    uuid_str = cfg.get("uuid_str") or ""
    trojan_pw = cfg.get("trojan_password") or uuid_str

    if protocol == "vless":
        inbound = {
            "type": "vless", "tag": "in", "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"uuid": uuid_str, "flow": ""}],
            "transport": {"type": "ws", "path": ws_path},
        }
    elif protocol == "trojan":
        inbound = {
            "type": "trojan", "tag": "in", "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"password": trojan_pw}],
            "transport": {"type": "ws", "path": ws_path},
        }
    else:
        inbound = {
            "type": "vmess", "tag": "in", "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"uuid": uuid_str, "alterId": 0}],
            "transport": {"type": "ws", "path": ws_path},
        }

    hop1 = parse_proxy_url(cfg.get("hop1"))
    hop2 = parse_proxy_url(cfg.get("hop2"))

    outbounds = []
    if hop1:
        outbounds.append(_clean_outbound(hop1, "hop1"))
    if hop2:
        outbounds.append(_clean_outbound(hop2, "hop2", detour="hop1" if hop1 else None))
    outbounds.append({"type": "direct", "tag": "direct"})

    final = "direct"
    if str(cfg.get("outbound_mode")) == MODE_PROXY:
        if hop2:
            final = "hop2"
        elif hop1:
            final = "hop1"

    return {
        "log": {"level": "info"},
        "inbounds": [inbound],
        "outbounds": outbounds,
        "route": {"final": final},
    }


def _vmess_link(server, port, uuid_str, sni, ws_path, name):
    obj = {
        "v": "2", "ps": name, "add": server, "port": str(port), "id": uuid_str,
        "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": sni, "path": ws_path, "tls": "tls", "sni": sni,
    }
    raw = json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("utf-8").rstrip("=")


def _vless_link(server, port, uuid_str, sni, ws_path, name):
    query = urlencode({
        "encryption": "none", "security": "tls", "sni": sni,
        "type": "ws", "host": sni, "path": ws_path,
    })
    host = f"[{server}]" if ":" in server else server
    return f"vless://{uuid_str}@{host}:{port}?{query}#{quote(name)}"


def _trojan_link(server, port, password, sni, ws_path, name):
    query = urlencode({
        "security": "tls", "sni": sni, "type": "ws",
        "host": sni, "path": ws_path,
    })
    host = f"[{server}]" if ":" in server else server
    return f"trojan://{quote(password)}@{host}:{port}?{query}#{quote(name)}"


def decode_node_link(link):
    """把一条节点链接解回 dict，用于自检。

    vmess 返回完整字段；vless/trojan 是 URL 形式，只取得到 host/sni/名称。
    解析不了就抛 ValueError —— 自检宁可报错，也不要静默放过。
    """
    link = str(link or "").strip()
    if link.startswith("vmess://"):
        raw = link[8:]
        pad = raw + "=" * (-len(raw) % 4)
        try:
            return json.loads(base64.b64decode(pad).decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"vmess 链接解码失败：{exc}") from exc
    if link.startswith(("vless://", "trojan://")):
        body, _, frag = link.partition("#")
        query = body.split("?", 1)[1] if "?" in body else ""
        params = dict(parse_qsl(query))
        return {"ps": unquote(frag), "host": params.get("host", ""),
                "sni": params.get("sni", "")}
    raise ValueError("无法识别的链接协议")


def validate_links(links, expected_domain):
    """自检生成的节点链接，返回问题描述列表（空列表表示全部正常）。

    这里只做「能不能自证一致」的检查，不改动任何链接：
    - 每条链接都要能解码；
    - host / sni 必须等于本次生成时用的隧道域名（不一致 = 客户端会握错 SNI，节点必然连不上）。
    """
    problems = []
    for idx, link in enumerate(links, 1):
        try:
            obj = decode_node_link(link)
        except ValueError as exc:
            problems.append(f"第 {idx} 条：{exc}")
            continue
        name = (obj.get("ps") or "").strip() or f"第 {idx} 条"
        for field in ("host", "sni"):
            value = str(obj.get(field) or "").strip()
            if value and expected_domain and value != expected_domain:
                problems.append(f"「{name}」的 {field} = {value}，与隧道域名 {expected_domain} 不一致")
    return problems


def parse_target_line(line, default_port=443):
    """解析一行优选地址，返回 (host, port, name)；无法解析时返回 None。

    支持：1.2.3.4 / 1.2.3.4:8443 / [2606:4700::1]:443 / 任意一种后面跟 #名称
    """
    line = str(line).strip()
    if not line or line.startswith("#"):
        return None
    name = ""
    if "#" in line:
        line, name = line.split("#", 1)
    line = line.strip()
    if not line:
        return None

    if line.startswith("["):                           # [IPv6] 或 [IPv6]:port
        m = re.match(r'^\[(.+)\](?::(\d+))?$', line)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else default_port
        else:
            host, port = line, default_port
    elif line.count(":") == 1:                         # IPv4:port
        host, _, port_raw = line.partition(":")
        port = int(port_raw) if port_raw.isdigit() else default_port
    else:                                              # 裸地址（含不带端口的 IPv6）
        host, port = line, default_port

    if not host or not (0 < port < 65536):
        return None
    return host, port, name.strip()


def tcp_latency(host, port=443, timeout=2.0):
    """测一次 TCP 握手耗时，返回毫秒；不可达返回 None。

    这里只做 TCP 握手，不做 TLS —— 目标是筛掉连都连不上的 IP，
    握手延迟已经足够区分好坏，而且省掉了证书校验的开销。
    """
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return int(round((time.perf_counter() - start) * 1000))
    except (OSError, ValueError):
        # socket.timeout 在 3.10+ 是 OSError 的子类，一并覆盖
        return None


def run_latency_test(candidates, port=443, timeout=2.0, threads=16, on_progress=None):
    """并发测速。

    candidates 可以是 [host, ...] 或 [(host, port), ...]。
    返回 [(host, port, ms), ...]，按延迟升序，只包含可达项。
    """
    jobs = []
    seen = set()
    for item in candidates:
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            host, p = str(item[0]), int(item[1])
        else:
            host, p = str(item), int(port)
        if not host or not (0 < p < 65536):
            continue
        dedupe_key = f"{host}:{p}"
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        jobs.append((host, p))

    if not jobs:
        return []

    total = len(jobs)
    done = 0
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(threads), total))) as pool:
        futures = {pool.submit(tcp_latency, host, p, timeout): (host, p) for host, p in jobs}
        for future in as_completed(futures):
            host, p = futures[future]
            try:
                ms = future.result()
            except Exception:
                ms = None
            done += 1
            if on_progress:
                try:
                    on_progress(done, total)
                except Exception:
                    pass
            if ms is not None:
                results.append((host, p, ms))

    results.sort(key=lambda r: r[2])
    return results


def validate_config(cfg):
    """校验配置，返回 (errors, warnings)。

    errors 会拒绝保存；warnings 只提醒，仍允许保存。

    出站地址是最容易填错又最难发现的地方：填错时 sing-box 会**静默忽略**那个 outbound，
    服务照常起来、订阅照常生成，但实际走的是直连。所以这里必须挡住。
    """
    errors = []
    warnings = []

    for field, label in (("hop1", "一级代理"), ("hop2", "落地节点")):
        raw = (cfg.get(field) or "").strip()
        if raw and parse_proxy_url(raw) is None:
            errors.append(f"{label}地址无法解析：{raw}")

    if str(cfg.get("outbound_mode")) == MODE_PROXY:
        if not (cfg.get("hop1") or "").strip() and not (cfg.get("hop2") or "").strip():
            warnings.append("出站模式选了「走代理链路」，但一级代理和落地节点都是空的，"
                            "实际会按直连处理。")

    if (cfg.get("protocol") or "").lower() == "trojan" and not cfg.get("uuid_str"):
        warnings.append("协议选了 trojan 但 UUID 为空，Trojan 密码也会跟着为空，客户端将无法认证。")

    return errors, warnings


def _recv_exact(sock, n):
    """从 socket 精确读 n 字节；对端提前关闭返回 None。

    TCP 是字节流，recv(n) 不保证一次给你 n 字节，握手协议必须按长度读够。
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def socks5_handshake(host, port, username="", password="", timeout=3.0):
    """做一次完整的 SOCKS5 握手（含账号密码认证），返回耗时毫秒；失败返回 None。

    只走到「认证通过」为止，不发起真实连接 —— 这已经足以确认
    地址、端口、账号、密码四项全对，而不用真的把流量打出去。
    """
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if username:
                sock.sendall(b"\x05\x02\x00\x02")      # 支持「无认证 + 用户名密码」两种
            else:
                sock.sendall(b"\x05\x01\x00")          # 只支持无认证

            resp = _recv_exact(sock, 2)
            if not resp or resp[0] != 0x05:
                return None                            # 不是 SOCKS5
            method = resp[1]

            if method == 0x02:                         # 服务端要求用户名密码
                user = username.encode("utf-8")
                pwd = password.encode("utf-8")
                if len(user) > 255 or len(pwd) > 255:
                    return None
                sock.sendall(b"\x01" + bytes([len(user)]) + user
                             + bytes([len(pwd)]) + pwd)
                auth = _recv_exact(sock, 2)
                if not auth or auth[1] != 0x00:
                    return None                        # 认证被拒
            elif method != 0x00:                       # 服务端要求的认证方式我们不支持
                return None

            return int(round((time.perf_counter() - start) * 1000))
    except (OSError, ValueError):
        return None


def probe_outbound(parsed, timeout=3.0):
    """探测一个出站节点是否可用，返回耗时毫秒，失败返回 None。

    socks → 完整 SOCKS5 握手，能验证账号密码
    http  → 只做 TCP 可达性探测（完整校验需要发真实请求，代价太大）
    """
    if not parsed:
        return None
    if parsed["type"] == "socks":
        return socks5_handshake(parsed["server"], parsed["server_port"],
                                parsed["username"], parsed["password"], timeout)
    return tcp_latency(parsed["server"], parsed["server_port"], timeout)


def probe_outbounds(items, timeout=3.0, threads=4, on_progress=None):
    """并发探测多个出站节点。

    items = [(label, parsed_dict), ...]，返回 {label: 毫秒或 None}。
    """
    if not items:
        return {}
    results = {}
    done = 0
    total = len(items)
    with ThreadPoolExecutor(max_workers=max(1, min(threads, total))) as pool:
        futures = {pool.submit(probe_outbound, parsed, timeout): label
                   for label, parsed in items}
        for future in as_completed(futures):
            label = futures[future]
            try:
                ms = future.result()
            except Exception:
                ms = None
            done += 1
            if on_progress:
                try:
                    on_progress(done, total)
                except Exception:
                    pass
            results[label] = ms
    return results


# ============================================================
# 出口 IP 检测
# ============================================================
# 这里要分清两件事，它们经常被混为一谈：
#   入口（优选 IP）—— 客户端从哪个 CDN 边缘接入，只影响这一段的速度和可达性
#   出口（本模块查的）—— 流量最终从哪个 IP 出去，由 sing-box 的出站决定
#
# 本项目的 sing-box 跑在 Streamlit 容器里，隧道是容器主动往外连的，
# 所以直连模式下出口恒等于容器所在地 —— 客户端连香港还是美国节点都不改变这一点。
# CFNext 之所以「选哪个地区就出哪个地区」，是因为它的代理代码跑在 Cloudflare 边缘上。

SOCKS5_REPLY_ERRORS = {
    0x01: "通用失败",
    0x02: "规则不允许连接",
    0x03: "网络不可达",
    0x04: "主机不可达",
    0x05: "目标拒绝连接",
    0x06: "TTL 超时",
    0x07: "不支持的命令",
    0x08: "不支持的地址类型",
}


def _socks5_negotiate(sock, username, password, dest_host, dest_port):
    """在一条已连上的 socket 上完成 SOCKS5 认证并 CONNECT 到目标。失败抛 OSError。

    和 socks5_handshake 的区别：那个只验到「认证通过」就收工，
    这个要真的把 CONNECT 发出去，好让调用方接着在隧道里跑流量。
    """
    if username:
        sock.sendall(b"\x05\x02\x00\x02")          # 无认证 + 用户名密码
    else:
        sock.sendall(b"\x05\x01\x00")              # 只要无认证

    resp = _recv_exact(sock, 2)
    if not resp or resp[0] != 0x05:
        raise OSError("对端不是 SOCKS5 代理")
    method = resp[1]

    if method == 0x02:
        user = username.encode("utf-8")
        pwd = password.encode("utf-8")
        if len(user) > 255 or len(pwd) > 255:
            raise OSError("账号或密码超过 255 字节")
        sock.sendall(b"\x01" + bytes([len(user)]) + user
                     + bytes([len(pwd)]) + pwd)
        auth = _recv_exact(sock, 2)
        if not auth or auth[1] != 0x00:
            raise OSError("SOCKS5 认证被拒绝")
    elif method != 0x00:
        raise OSError(f"代理要求不支持的认证方式 0x{method:02x}")

    # 目标地址按类型打包：IPv4 / IPv6 / 域名
    try:
        addr = b"\x01" + socket.inet_aton(dest_host)
    except OSError:
        try:
            addr = b"\x04" + socket.inet_pton(socket.AF_INET6, dest_host)
        except OSError:
            try:
                hb = dest_host.encode("idna")
            except UnicodeError:
                raise OSError(f"域名无法编码：{dest_host}")
            if len(hb) > 255:
                raise OSError("域名超过 255 字节")
            addr = b"\x03" + bytes([len(hb)]) + hb

    sock.sendall(b"\x05\x01\x00" + addr
                 + bytes([(dest_port >> 8) & 0xFF, dest_port & 0xFF]))

    rep = _recv_exact(sock, 4)
    if not rep:
        raise OSError("代理没有返回 CONNECT 结果")
    if rep[1] != 0x00:
        raise OSError("SOCKS5 " + SOCKS5_REPLY_ERRORS.get(rep[1], f"错误码 0x{rep[1]:02x}"))

    # 吃掉绑定地址 + 端口，不回读的话后面第一个字节会被它们污染
    atyp = rep[3]
    if atyp == 0x01:
        _recv_exact(sock, 4)
    elif atyp == 0x04:
        _recv_exact(sock, 16)
    elif atyp == 0x03:
        ln = _recv_exact(sock, 1)
        _recv_exact(sock, ln[0] if ln else 0)
    _recv_exact(sock, 2)


def _http_connect_negotiate(sock, dest_host, dest_port):
    """在一条已连上的 socket 上发 HTTP CONNECT 建隧道。失败抛 OSError。"""
    req = (f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
           f"Host: {dest_host}:{dest_port}\r\n\r\n")
    sock.sendall(req.encode("ascii"))

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            raise OSError("HTTP 代理提前断开")
        buf += chunk
        if len(buf) > 8192:
            raise OSError("HTTP 代理响应异常")
    # CONNECT 的 200 响应没有 body，所以不会有多读出来的隧道数据
    status = buf.split(b"\r\n", 1)[0].decode("latin-1")
    if " 200" not in status:
        raise OSError(f"HTTP 代理拒绝 CONNECT：{status.strip()}")


def _dial_through(chain, dest_host, dest_port, timeout=8.0):
    """沿 chain 逐级建隧道，返回一条连到目标的 socket。

    chain 里每项都是一个已解析的出站节点（hop1 在前、hop2 在后）。
    逐级 CONNECT 嵌套 —— 和 sing-box 里 hop2 用 detour 挂 hop1 的语义一致：
    容器 -> hop1 -> hop2 -> 目标。

    chain 为空时就是直连。
    """
    if not chain:
        sock = socket.create_connection((dest_host, dest_port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

    head = chain[0]
    sock = socket.create_connection((head["server"], head["server_port"]), timeout=timeout)
    sock.settimeout(timeout)
    try:
        for i, hop in enumerate(chain):
            nxt = chain[i + 1] if i + 1 < len(chain) else None
            target_host, target_port = (nxt["server"], nxt["server_port"]) if nxt \
                else (dest_host, dest_port)
            if hop["type"] == "http":
                _http_connect_negotiate(sock, target_host, target_port)
            else:
                _socks5_negotiate(sock, hop["username"], hop["password"],
                                  target_host, target_port)
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def _dechunk(sock, body):
    """把 chunked 编码的 body 解出来（body 是已经读到的部分）。"""
    out = b""
    while True:
        while b"\r\n" not in body:
            chunk = sock.recv(4096)
            if not chunk:
                return out
            body += chunk
        size_line, body = body.split(b"\r\n", 1)
        try:
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            raise OSError("chunked 长度字段无法解析")
        if size == 0:
            return out
        while len(body) < size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                return out
            body += chunk
        out += body[:size]
        body = body[size + 2:]


def _read_http_body(sock, limit=65536):
    """从 socket 读一个完整的 HTTP 响应，返回 body 文本。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise OSError("响应头过大")
    if b"\r\n\r\n" not in buf:
        raise OSError("响应不完整")

    head, body = buf.split(b"\r\n\r\n", 1)
    head_text = head.decode("latin-1")
    status = head_text.split("\r\n", 1)[0]
    if " 200" not in status:
        raise OSError(f"接口返回 {status.strip()}")

    headers = {}
    for line in head_text.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if headers.get("transfer-encoding", "").lower() == "chunked":
        return _dechunk(sock, body).decode("utf-8", "ignore")

    if "content-length" in headers:
        try:
            need = int(headers["content-length"])
        except ValueError:
            raise OSError("Content-Length 无法解析")
        while len(body) < need:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
        return body[:need].decode("utf-8", "ignore")

    # 既没有 Content-Length 也不是 chunked：读到对端关闭为止
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
        if len(body) > limit:
            break
    return body.decode("utf-8", "ignore")


def _http_get_json(host, port, use_tls, path, chain, timeout=8.0):
    """经 chain（可为空 = 直连）发一个 GET，返回解析后的 JSON。"""
    sock = _dial_through(chain, host, port, timeout)
    try:
        if use_tls:
            # wrap_socket 会接管底层 socket，之后只关外层即可
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: application/json\r\n"
               "Connection: close\r\n\r\n")
        sock.sendall(req.encode("ascii"))
        text = _read_http_body(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return json.loads(text)


def _parse_ip_api(payload):
    """ip-api.com 的返回：{"status":"success","query":"1.2.3.4","countryCode":"US",...}"""
    if payload.get("status") != "success":
        raise ValueError(payload.get("message") or "接口返回失败状态")
    return payload.get("query") or "", payload.get("countryCode") or "", payload.get("country") or ""


def _parse_country_is(payload):
    """api.country.is 的返回：{"ip":"1.2.3.4","country":"US"}"""
    return payload.get("ip") or "", payload.get("country") or "", ""


# 按顺序试，前一个失败就换下一个。
# 第一个走明文 HTTP —— 不依赖 TLS，能穿过只放行 80 端口的代理；代价是最后一段不加密，
# 但出口 IP 这种公开信息被中间人篡改没有意义，可靠性比这点隐私重要。
EXIT_CHECK_APIS = [
    ("ip-api.com", 80, False, "/json/?fields=status,message,query,country,countryCode",
     _parse_ip_api),
    ("api.country.is", 443, True, "/", _parse_country_is),
]


def build_outbound_chain(cfg):
    """按配置拼出出站链路，返回 [parsed, ...]（hop1 在前、hop2 在后）。

    直连模式返回空列表。只保留能解析的项 —— 和 build_singbox_config 的取舍一致。
    """
    if str(cfg.get("outbound_mode")) != MODE_PROXY:
        return []
    chain = []
    for field in ("hop1", "hop2"):
        parsed = parse_proxy_url(cfg.get(field))
        if parsed:
            chain.append(parsed)
    return chain


def _describe_hop(parsed):
    label = "HTTP 代理" if parsed["type"] == "http" else "SOCKS5"
    return f"{label} {parsed['server']}:{parsed['server_port']}"


def query_exit_ip(cfg, timeout=8.0):
    """查询当前出站链路的真实出口，返回 (info, error)。

    info = {"ip", "code", "country", "via"}，country 已转成中文。
    """
    chain = build_outbound_chain(cfg)
    via = " → ".join(_describe_hop(p) for p in chain) if chain else "直连（容器出口）"

    errors = []
    for host, port, use_tls, path, parser in EXIT_CHECK_APIS:
        try:
            payload = _http_get_json(host, port, use_tls, path, chain, timeout)
            ip, code, country = parser(payload)
            if not ip:
                raise ValueError("接口没返回 IP")
            code = (code or "").upper()
            return {
                "ip": ip,
                "code": code,
                "country": REGION_CN.get(code) or country or code or "未知",
                "via": via,
            }, ""
        except Exception as e:
            errors.append(f"{host}: {type(e).__name__}: {e}")
    return None, "；".join(errors)


def _is_region_stopword(seg):
    """判断一个中文段是不是源的固定前缀词，而不是地区名。

    双向包含判断：源里写法不统一，可能是「地区随机」「随机优选」「优选」，
    也可能被截成「随机」。只做精确匹配漏一个，前缀词就会被当成地区名返回
    （实测「随机 | DE」返回「随机」而不是「德国」）。
    """
    return any(sw in seg or seg in sw for sw in REGION_NAME_STOPWORDS)


def extract_region_name(raw_name):
    """从数据源的名称字段里提取地区中文名，提取不到返回空字符串。

    移植自 CFNext 的同名逻辑，适配 bestcf 的行格式：
        IP:端口#地区随机 | 香港 HK | HKG | IP:端口

    提取顺序（每一步都是为了不被源的固定前缀骗到）：
      1. 开头就是「中文 + 空格 + 地区码」→ 取中文（锚定开头，避免"澳大利亚"被截成"大利亚"）
      2. 「|」分段里找「中文 + 空格 + 地区码」的整段 → 取中文
      3. 「|」分段里找纯中文段，排除「地区随机」这类前缀词
      4. 兜底：找 2 位大写地区码，查 REGION_CN

    只返回纯地区名（「香港」），编号不在这里做 —— 见 assign_unique_names。
    """
    raw = (raw_name or "").strip()
    if not raw:
        return ""

    # 不含中文、也不含「|」的名称：
    #   纯地区码（HK / DE）查表转成中文，其它（JP-A-147）当作用户自定义名原样保留
    if not re.search(r'[\u4e00-\u9fa5]', raw) and "|" not in raw:
        if re.fullmatch(r'[A-Za-z]{2}', raw) and raw.upper() in REGION_CN:
            return REGION_CN[raw.upper()]
        return raw

    m = re.match(r'^\s*([\u4e00-\u9fa5]{2,5})\s+[A-Z]{2}', raw)
    if m and not _is_region_stopword(m.group(1)):
        return m.group(1)

    segments = [s.strip() for s in raw.split("|")]

    for seg in segments:
        m = re.match(r'^([\u4e00-\u9fa5]{2,5})\s+[A-Z]{2}$', seg)
        if m:
            return m.group(1)

    for seg in segments:
        if re.fullmatch(r'[\u4e00-\u9fa5]{2,5}', seg) and not _is_region_stopword(seg):
            return seg

    m = re.search(r'\b([A-Z]{2})\b', raw)
    if m:
        return REGION_CN.get(m.group(1), m.group(1))

    return ""


def _is_valid_ipv4(ip):
    parts = str(ip).split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def parse_region_pool_text(text, limit=100):
    """解析地区优选源文本，返回 [(ip, port, name), ...]。

    兼容三种行格式：纯 IP / IP:端口 / IP:端口#名称。
    同源内按 ip:端口 去重。

    name 是纯地区名（「香港」），不带编号 —— 编号统一由 assign_unique_names
    在写入优选列表时分配。放在这里编号会导致：同一地区分两次拉取时，
    第二批又从 香港-01 开始，和第一批撞名。
    """
    results = []
    seen = set()
    for raw in (text or "").splitlines():
        if len(results) >= limit:
            break
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?:#([^\r\n]*))?', raw)
        if not m:
            continue
        ip = m.group(1)
        if not _is_valid_ipv4(ip):
            continue
        port = int(m.group(2)) if m.group(2) else 443
        if not (0 < port < 65536):
            continue
        key = f"{ip}:{port}"
        if key in seen:
            continue
        seen.add(key)
        results.append((ip, port, extract_region_name(m.group(3) or "")))
    return results


def fetch_region_pool(url, limit=100, timeout=10.0):
    """拉取一个地区优选源并解析，返回 (items, error)。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "ignore")
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"

    items = parse_region_pool_text(text, limit)
    if not items:
        return [], "源里没有解析出可用地址"
    return items, ""


def build_node_links(domain, cfg):
    """按当前协议生成节点链接列表。顺序：自定义优选 IP → 自定义域名 → 隧道域名。"""
    protocol = (cfg.get("protocol") or "vmess").lower()
    ws_path = normalize_path(cfg.get("ws_path"))
    uuid_str = cfg.get("uuid_str") or ""
    password = cfg.get("trojan_password") or uuid_str

    targets = []
    seen = set()

    for line in cfg.get("preferred_ips") or []:
        parsed = parse_target_line(line)
        if not parsed:
            continue
        ip, port, name = parsed
        key = f"{ip}:{port}"
        if key in seen:
            continue
        seen.add(key)
        targets.append((ip, port, name or f"优选-{ip}"))

    custom_domain = (cfg.get("preferred_domain") or "").strip()
    if custom_domain and f"{custom_domain}:443" not in seen:
        seen.add(f"{custom_domain}:443")
        targets.append((custom_domain, 443, "自定义域名"))

    if domain and f"{domain}:443" not in seen:
        targets.append((domain, 443, "隧道直连"))

    links = []
    for server, port, name in targets:
        # 名称直接用：数据源带来的地区名（香港-01）、用户自定义名（JP-A-147）、
        # 或兜底的「优选-1.2.3.4」。不再追加主机名前缀，保持和 CFNext 一致的清爽命名。
        if protocol == "vless":
            links.append(_vless_link(server, port, uuid_str, domain, ws_path, name))
        elif protocol == "trojan":
            links.append(_trojan_link(server, port, password, domain, ws_path, name))
        else:
            links.append(_vmess_link(server, port, uuid_str, domain, ws_path, name))
    return links


def generate_all_configs(domain, cfg, port_vm_ws):
    """生成节点链接并落盘，返回用于界面显示的文本。"""
    links = build_node_links(domain, cfg)
    ALL_NODES_FILE.write_text("\n".join(links) + "\n", encoding="utf-8")

    # 自检：链接必须自证一致（host/sni 都等于本次的隧道域名）。
    # 出问题时不藏起来 —— 面板上直接标出来，否则用户拿到的是「看着正常、连不上」的节点。
    problems = validate_links(links, domain)

    mode_text = "走代理链路" if str(cfg.get("outbound_mode")) == MODE_PROXY else "直连"
    output_text = f"""
✅ **服务已启动**
---
- **协议:** `{(cfg.get('protocol') or 'vmess').upper()}`
- **域名 (Domain):** `{domain}`
- **UUID:** `{cfg.get('uuid_str') or ''}`
- **本地端口:** `{port_vm_ws}`
- **WebSocket 路径:** `{normalize_path(cfg.get('ws_path'))}`
- **出站模式:** `{mode_text}`
---
**节点链接（共 {len(links)} 条，可复制）:**
""" + "\n".join(links)

    if problems:
        output_text += (f"\n\n⚠️ **自检发现 {len(problems)} 处问题**"
                        f"（这些节点的 SNI 与隧道域名对不上，客户端会握手失败）：\n"
                        + "\n".join(f"- {p}" for p in problems))

    LIST_FILE.write_text(output_text, encoding="utf-8")
    return output_text


def _pid_alive(pid):
    """判断 PID 对应进程是否存在。

    注意：Windows 上 os.kill(pid, 0) 不是「探测」，而是直接调用 TerminateProcess
    把目标进程杀掉（退出码 0），所以这里必须先做平台判断。
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False

    if platform.system() == "Windows":
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                 capture_output=True, text=True, timeout=10)
            return str(pid) in (out.stdout or "")
        except Exception:
            return False

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # 进程存在，只是不属于当前用户
    except (ValueError, OSError):
        return False


def _pid_matches(pid, keyword, proc_root="/proc"):
    """读 /proc/<pid>/cmdline 确认进程身份，避免 PID 复用导致的误判。

    非 Linux 平台或读不到时退化为「不校验身份」，返回 True。
    proc_root 可注入，便于在非 Linux 上测试这段逻辑。
    """
    cmdline_path = Path(proc_root) / str(pid) / "cmdline"
    try:
        if not cmdline_path.exists():
            return True
        raw = cmdline_path.read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")
    except Exception:
        return True
    if not raw.strip():
        return False         # 僵尸进程，cmdline 为空
    return keyword in raw


def stop_services():
    """停止所有由本脚本启动的后台服务进程。"""
    for pid_file in [SB_PID_FILE, ARGO_PID_FILE]:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 9)  # 强制终止进程
            except (ValueError, ProcessLookupError, FileNotFoundError, PermissionError):
                pass
            finally:
                pid_file.unlink(missing_ok=True)  # 删除PID文件
    # 作为最后的保险措施，按名字查找并杀死进程（仅 Linux 有 pkill）
    if platform.system() == "Linux":
        subprocess.run("pkill -9 -f 'sing-box run'", shell=True, capture_output=True)
        subprocess.run("pkill -9 -f 'cloudflared tunnel'", shell=True, capture_output=True)


def is_service_running():
    """检查核心服务是否在运行：既要 PID 存活，也要确认进程身份对得上。"""
    if not SB_PID_FILE.exists() or not ARGO_PID_FILE.exists():
        return False
    try:
        sb_pid = int(SB_PID_FILE.read_text().strip())
        argo_pid = int(ARGO_PID_FILE.read_text().strip())
    except (ValueError, FileNotFoundError):
        return False
    return (_pid_alive(sb_pid) and _pid_matches(sb_pid, "sing-box")
            and _pid_alive(argo_pid) and _pid_matches(argo_pid, "cloudflared"))


def get_tunnel_domain():
    """从argo日志文件中尝试读取Cloudflare临时隧道域名。"""
    for _ in range(15):  # 最多等待30秒
        if LOG_FILE.exists():
            try:
                log_content = LOG_FILE.read_text(encoding="utf-8", errors="ignore")
                match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_content)
                if match:
                    return match.group(1)
            except Exception:
                pass
        time.sleep(2)
    return None


# --- 核心逻辑 ---

def start_services(cfg, silent=False):
    """核心函数：按配置安装并启动服务，可选择静默模式。"""
    if not silent:
        st.info("🔄 正在启动/重启服务...")

    stop_services()

    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)

        # UUID 与端口若未指定，生成一次并持久化，避免每次重启节点全部失效
        runtime = load_runtime_config()
        uuid_str = cfg.get("uuid_str") or ""
        port_vm_ws = int(cfg.get("port_vm_ws") or 0)
        changed = False
        if not uuid_str:
            uuid_str = str(uuid.uuid4())
            runtime["uuid_str"] = uuid_str
            changed = True
        if not port_vm_ws:
            port_vm_ws = random.randint(10000, 65535)
            runtime["port_vm_ws"] = port_vm_ws
            changed = True
        if changed:
            save_runtime_config({**DEFAULT_CONFIG, **runtime})

        effective_cfg = {**cfg, "uuid_str": uuid_str, "port_vm_ws": port_vm_ws}

        # 定义依赖项及其下载逻辑
        arch = "amd64" if "x86_64" in platform.machine().lower() else "arm64"
        singbox_path = INSTALL_DIR / "sing-box"
        cloudflared_path = INSTALL_DIR / "cloudflared"

        # 封装下载和安装过程
        def install_dependencies():
            if not singbox_path.exists():
                sb_version, sb_name_actual = "1.9.0-beta.11", f"sing-box-1.9.0-beta.11-linux-{arch}"
                tar_path = INSTALL_DIR / "sing-box.tar.gz"
                if not download_file(f"https://github.com/SagerNet/sing-box/releases/download/v{sb_version}/{sb_name_actual}.tar.gz", tar_path, silent):
                    return False, "sing-box 下载失败。"
                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(path=INSTALL_DIR)
                shutil.move(INSTALL_DIR / sb_name_actual / "sing-box", singbox_path)
                shutil.rmtree(INSTALL_DIR / sb_name_actual)
                tar_path.unlink()
                os.chmod(singbox_path, 0o755)

            if not cloudflared_path.exists():
                cf_arch = "amd64" if arch == "amd64" else "arm"
                if not download_file(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", cloudflared_path, silent):
                    return False, "cloudflared 下载失败。"
                os.chmod(cloudflared_path, 0o755)
            return True, ""

        # 根据是否为静默模式，决定是否显示 spinner
        if not silent:
            with st.spinner("正在检查并安装依赖 (sing-box, cloudflared)..."):
                success, msg = install_dependencies()
                if not success:
                    return False, msg
        else:
            success, msg = install_dependencies()
            if not success:
                return False, msg

        # 按面板配置生成 sing-box 配置文件
        sb_config = build_singbox_config(effective_cfg)
        SB_CONFIG_FILE.write_text(
            json.dumps(sb_config, indent=2, ensure_ascii=False), encoding="utf-8")

        # 启动 sing-box 和 cloudflared 进程
        with open(SB_LOG_FILE, "w") as sb_log, open(LOG_FILE, "w") as cf_log:
            sb_process = subprocess.Popen(
                [str(singbox_path), 'run', '-c', SB_CONFIG_FILE.name],
                cwd=INSTALL_DIR, stdout=sb_log, stderr=subprocess.STDOUT)
            SB_PID_FILE.write_text(str(sb_process.pid))

            argo_token = cfg.get("argo_token") or ""
            if argo_token:
                cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate', 'run', '--token', argo_token]
            else:
                cf_cmd = [str(cloudflared_path), 'tunnel', '--no-autoupdate',
                          '--url', f'http://localhost:{port_vm_ws}', '--protocol', 'http2']
            cf_process = subprocess.Popen(cf_cmd, cwd=INSTALL_DIR, stdout=cf_log, stderr=subprocess.STDOUT)
            ARGO_PID_FILE.write_text(str(cf_process.pid))

        # 等待并获取域名
        time.sleep(5)
        custom_domain = cfg.get("custom_domain") or ""
        final_domain = custom_domain or (get_tunnel_domain() if not argo_token else None)
        if not final_domain:
            return False, "未能确定隧道域名。请检查日志 (`.agsb/argo.log`)。"

        links_output = generate_all_configs(final_domain, effective_cfg, port_vm_ws)
        return True, links_output

    except Exception as e:
        return False, f"处理过程中发生意外错误: {e}"


def uninstall_services():
    """卸载服务，清理所有运行时文件和进程。"""
    stop_services()
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
    st.session_state.clear()


# --- UI 渲染函数 ---

def set_flash(kind, message):
    """记录一条提示，供下一次 rerun 后显示。

    st.rerun() 会丢弃本次运行已经渲染的内容，所以提示必须先存进 session_state。
    """
    st.session_state["_flash"] = (kind, message)


def render_flash():
    """显示并清除上一步留下的提示。"""
    flash = st.session_state.pop("_flash", None)
    if not flash:
        return
    kind, message = flash
    if kind == "success":
        st.success(message)
    elif kind == "error":
        st.error(message)
    else:
        st.info(message)


# 表单里「优选 IP」文本框的 session_state 键。测速结果要靠它回填，所以必须显式命名。
KEY_PREFERRED_IPS = "cfg_preferred_ips"
KEY_TEST_RESULTS = "_test_results"
KEY_PENDING_ADD = "_pending_add_ips"
# 待加入节点的附带说明（比如「哪个来源拉失败了」）。
# 单独放一个键是因为 set_flash 是覆盖式的：render_region_sources 和
# apply_pending_preferred_ips 都会写提示，后写的会把前一个顶掉。
KEY_PENDING_NOTE = "_pending_add_note"
# 出口检测结果。存下来是为了 rerun 之后还能看到，不用反复点检测。
KEY_EXIT_RESULT = "_exit_check_result"


def apply_pending_preferred_ips(secrets_cfg):
    """把待加入的节点（测速结果 / 地区优选源）回填进「优选 IP」文本框。

    必须在表单控件被创建之前调用 —— 控件一旦实例化，它的 session_state 键就不能再改了。
    所以流程是：点「加入优选」→ 记下待办 → rerun → 这里在渲染前写进控件状态。
    重名编号和提示也统一在这里做，保证两个来源走同一条路径。
    """
    pending = st.session_state.pop(KEY_PENDING_ADD, None)
    if not pending:
        return
    note = st.session_state.pop(KEY_PENDING_NOTE, "")

    if KEY_PREFERRED_IPS in st.session_state:
        current = st.session_state[KEY_PREFERRED_IPS]
    else:
        current = "\n".join(resolve_config(secrets_cfg).get("preferred_ips") or [])

    lines = [l.strip() for l in str(current).splitlines() if l.strip()]
    seen = set()
    for l in lines:
        parsed = parse_target_line(l)
        if parsed:
            seen.add(f"{parsed[0]}:{parsed[1]}")

    fresh = []
    for entry in pending:
        parsed = parse_target_line(entry)
        if not parsed:
            continue
        key = f"{parsed[0]}:{parsed[1]}"
        if key in seen:
            continue
        seen.add(key)
        fresh.append(entry)

    # 重名的地区节点在这里统一编号（香港-01、香港-02…）。
    # 放在写入前而不是解析阶段，是为了让「同一地区分两次拉取」能接着上一批编号。
    lines.extend(assign_unique_names(fresh, lines))
    added = len(fresh)

    st.session_state[KEY_PREFERRED_IPS] = "\n".join(lines)
    if added:
        # 不说「测速结果」—— 这里也可能是地区优选源拉来的，措辞要能同时覆盖两种来源
        msg = f"已把 {added} 个节点加入优选列表，记得点「保存并生效」才会下发。"
        if note:
            set_flash("info", msg + " 但有来源失败：" + note)
        else:
            set_flash("success", msg)
    else:
        # 全部重复也不能把来源失败的说明吞掉 —— 否则用户以为「只是重复了」，
        # 实际上有个源根本没拉成功。
        msg = "这些节点已经在优选列表里了，没有重复添加。"
        if note:
            set_flash("info", msg + " 另有来源失败：" + note)
        else:
            set_flash("info", msg)


def format_target(host, port, default_port=443):
    """把 (host, port) 格式化成一行优选地址，443 时省略端口，IPv6 加方括号。

    表格展示和「加入优选」都走这里，保证看到的就是加进去的。
    """
    if ":" in host:                      # IPv6 必须加括号，否则和端口分隔符混淆
        host = f"[{host}]"
    return host if int(port) == default_port else f"{host}:{port}"


_NAME_TAIL_RE = re.compile(r'^(?P<base>.+?)-(?P<num>\d{1,3})$')


def assign_unique_names(entries, existing_lines):
    """给待加入的条目分配不重名的节点名，返回可直接写进优选框的行。

    为什么要单独一层：地区源一拉就是十几个同名节点（全是「香港」），
    不编号的话客户端节点列表里一屏重名，根本分不清哪个是哪个。

    规则：
      - 名字已带 -NN 后缀的原样保留（用户手工编的号不动）
      - 纯名字在本批里出现多次，或已存在于优选列表 → 接着同地区最大编号往后编
        （已有 香港-01..03，新来 10 个 → 香港-04..13）
      - 只出现一次且不重名 → 保持纯名字，不加多余后缀
      - 没有名字的条目不加名字，交给 build_node_links 兜底成「优选-1.2.3.4」

    调用方负责按 ip:端口 去重，这里只管名字。
    """
    used = set()
    maxnum = {}
    for line in existing_lines or []:
        parsed = parse_target_line(line)
        if not parsed or not parsed[2]:
            continue
        nm = parsed[2]
        used.add(nm)
        m = _NAME_TAIL_RE.match(nm)
        if m:
            base, num = m.group("base"), int(m.group("num"))
            maxnum[base] = max(maxnum.get(base, 0), num)

    parsed_entries = []
    for entry in entries or []:
        parsed = parse_target_line(entry)
        if parsed:
            parsed_entries.append(parsed)

    batch_count = {}
    for _, _, nm in parsed_entries:
        if nm:
            batch_count[nm] = batch_count.get(nm, 0) + 1

    out = []
    for host, port, nm in parsed_entries:
        addr = format_target(host, port)
        if not nm:
            out.append(addr)
            continue
        if _NAME_TAIL_RE.match(nm):       # 用户已编号，原样保留
            out.append(f"{addr}#{nm}")
            continue
        # 已经出现过同地区的编号变体（香港-01），新来的也得编号，
        # 否则会出现「香港」和「香港-01」并存的怪样子。
        if batch_count.get(nm, 0) <= 1 and nm not in used and nm not in maxnum:
            used.add(nm)
            out.append(f"{addr}#{nm}")
            continue
        n = maxnum.get(nm, 0) + 1
        while f"{nm}-{n:02d}" in used:
            n += 1
        final = f"{nm}-{n:02d}"
        used.add(final)
        maxnum[nm] = n
        out.append(f"{addr}#{final}")
    return out


def render_region_sources(cfg):
    """地区优选源：一键拉取自带地区标记的节点池，节点名自动带国家/地区名。

    必须放在 st.form 之外（按钮要独立响应）。
    """
    with st.expander("🌏 地区优选源（节点自动带国家/地区名）", expanded=False):
        st.caption("拉取社区维护的地区优选池。这些源下发的每一行都自带地区标记，"
                   "节点名会变成「香港-01」「日本-02」这种形式 —— "
                   "地区名来自源的标记，不是拿 IP 去反查地理位置。"
                   "同一地区重复拉取会接着上次的编号（香港-11、香港-12…）。"
                   "（地区池是 IPv4 的；要加 IPv6 请直接在下面的优选列表里手写。）")

        options = [f"{cn}（{code}）" for code, cn, _ in REGION_SOURCES]
        selected = st.multiselect("选择地区", options=options, default=options[:1],
                                  key="region_pick")

        rc1, rc2 = st.columns([1, 2])
        per_region = rc1.number_input("每个地区取多少个", min_value=1, max_value=100,
                                      value=10, key="region_count")
        custom_url = rc2.text_input("自定义源 URL（可选）", key="region_custom",
                                    placeholder="https://example.com/list.txt",
                                    help="每行一条，支持 纯IP / IP:端口 / IP:端口#名称")

        if st.button("🚀 拉取并加入优选", key="fetch_regions"):
            jobs = [(cn, url) for code, cn, url in REGION_SOURCES if f"{cn}（{code}）" in selected]
            if custom_url.strip():
                jobs.append(("自定义源", custom_url.strip()))

            if not jobs:
                st.warning("没有选择任何来源。")
            else:
                picked = []
                errors = []
                progress = st.progress(0.0, text="拉取中…")
                for i, (label, url) in enumerate(jobs, 1):
                    progress.progress(i / len(jobs), text=f"拉取中… {label}")
                    items, err = fetch_region_pool(url, limit=int(per_region))
                    if err:
                        errors.append(f"{label}（{err}）")
                        continue
                    for ip, port, name in items:
                        entry = format_target(ip, port)
                        if name:
                            entry += f"#{name}"
                        picked.append(entry)
                progress.empty()

                if picked:
                    st.session_state[KEY_PENDING_ADD] = picked
                    # 失败的来源不在这里提示 —— apply_pending_preferred_ips 的 set_flash
                    # 会把它顶掉。存成备注，由那边合并成一条提示。
                    st.session_state[KEY_PENDING_NOTE] = "；".join(errors)
                    st.rerun()
                else:
                    st.error("一个源都没拉成功：" + "；".join(errors))


def render_speed_test(cfg):
    """渲染「在线优选测速」模块。

    注意：必须放在 st.form 之外 —— 表单内的按钮会触发提交，拿不到独立的点击事件。
    """
    with st.expander("📡 在线优选测速", expanded=False):
        st.caption("从当前容器直连测 TCP 握手延迟，用来筛掉连不上的 IP。"
                   "测速由本机发出，建议测之前先确认容器网络正常。")

        default_src = "\n".join(cfg.get("preferred_ips") or [])
        test_input = st.text_area(
            "待测地址（每行一条，支持 IP、IP:端口、[IPv6]:端口，可跟 #名称）",
            value=default_src, height=130, key="test_src",
            placeholder="104.16.0.1\n104.17.0.1:8443\n[2606:4700::1]:443")

        tc1, tc2, tc3 = st.columns(3)
        test_port = tc1.number_input("默认端口", min_value=1, max_value=65535,
                                     value=443, key="test_port")
        test_timeout = tc2.slider("单次超时（秒）", min_value=1.0, max_value=5.0,
                                  value=2.0, step=0.5, key="test_timeout")
        test_threads = tc3.slider("并发数", min_value=4, max_value=64,
                                  value=16, step=4, key="test_threads")

        if st.button("🚀 开始测速", key="run_test"):
            candidates = []
            for line in str(test_input).splitlines():
                parsed = parse_target_line(line, default_port=int(test_port))
                if parsed:
                    candidates.append((parsed[0], parsed[1]))
            if not candidates:
                st.warning("没有解析出可测的地址，检查一下输入格式。")
            else:
                progress = st.progress(0.0, text=f"测速中… 0/{len(candidates)}")

                def on_progress(done, total):
                    progress.progress(done / total, text=f"测速中… {done}/{total}")

                results = run_latency_test(
                    candidates,
                    port=int(test_port),
                    timeout=float(test_timeout),
                    threads=int(test_threads),
                    on_progress=on_progress,
                )
                progress.empty()
                st.session_state[KEY_TEST_RESULTS] = results
                set_flash("success", f"测速完成：{len(candidates)} 个地址中 {len(results)} 个可达。")
                st.rerun()

        results = st.session_state.get(KEY_TEST_RESULTS)
        if results:
            st.markdown(f"**测速结果**（{len(results)} 个可达，按延迟升序）")
            st.dataframe(
                [{"地址": format_target(ip, port, int(test_port)),
                  "主机": ip, "端口": port, "延迟(ms)": ms}
                 for ip, port, ms in results],
                use_container_width=True, hide_index=True)

            ac1, ac2 = st.columns([1, 2])
            add_count = ac1.number_input("加入前 N 个", min_value=1,
                                         max_value=len(results), value=min(10, len(results)),
                                         key="add_count")
            if ac2.button("➕ 加入优选节点", key="add_best", use_container_width=True):
                picked = [f"{format_target(ip, port, int(test_port))}#测速{ms}ms"
                          for ip, port, ms in results[:int(add_count)]]
                st.session_state[KEY_PENDING_ADD] = picked
                st.session_state.pop(KEY_PENDING_NOTE, None)   # 测速这条路没有来源备注
                st.rerun()

            if st.button("🗑️ 清空测速结果", key="clear_results"):
                st.session_state.pop(KEY_TEST_RESULTS, None)
                st.rerun()


def render_outbound_test(cfg):
    """测试「已保存的」出站链路是否可用。

    只对当前已保存的配置生效 —— 表单里还没保存的改动测不到，这是刻意的：
    保存前的值在 Streamlit 里拿不到，而且「先保存再测」的流程更不容易误判。
    """
    if str(cfg.get("outbound_mode")) != MODE_PROXY:
        return

    hops = []
    for field, label in (("hop1", "一级代理"), ("hop2", "落地节点")):
        parsed = parse_proxy_url(cfg.get(field))
        if parsed:
            hops.append((label, parsed))

    with st.expander("🔌 出站链路连通性测试", expanded=False):
        if not hops:
            st.warning("出站模式选了「走代理链路」，但一级代理和落地节点都是空的 —— "
                       "现在实际走的是直连。去「落地与出站」里填上再保存。")
            return

        chain = " → ".join(
            ["容器"] + [f"{label}（{p['server']}:{p['server_port']}）" for label, p in hops] + ["目标"])
        st.caption(f"链路：{chain}")
        st.caption("socks5 会做完整握手（含账号密码校验）；http 只探测端口可达性。")

        if st.button("🚀 测试出站链路", key="run_outbound_test"):
            progress = st.progress(0.0, text="测试中…")

            def on_progress(done, total):
                progress.progress(done / total, text=f"测试中… {done}/{total}")

            results = probe_outbounds(hops, timeout=3.0, threads=4, on_progress=on_progress)
            progress.empty()
            st.session_state["_outbound_results"] = results

        results = st.session_state.get("_outbound_results")
        if results is not None:
            rows = []
            for label, parsed in hops:
                ms = results.get(label)
                rows.append({
                    "节点": label,
                    "地址": f"{parsed['server']}:{parsed['server_port']}",
                    "协议": parsed["type"],
                    "结果": f"可用（{ms}ms）" if ms is not None else "不可达 / 认证失败",
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)

            if all(ms is not None for ms in results.values()):
                st.success("✅ 链路上各跳都通了。")
            else:
                st.error("❌ 有节点不通。逐项检查：地址端口对不对、账号密码对不对、"
                         "对方防火墙有没有放行你的来源 IP。")


def render_exit_check(cfg):
    """出口 IP 检测：查流量最终从哪个 IP 出去。

    必须放在 st.form 之外（按钮要独立响应）。
    """
    with st.expander("🔍 出口 IP 检测", expanded=False):
        st.caption("这里查的是**流量最终从哪个 IP 出去**。"
                   "它和你在「地区优选源」里选的入口节点在哪个国家**没有关系** —— "
                   "入口只决定客户端从哪个 CDN 边缘接入，出口由 sing-box 的出站决定。")

        entries = []
        for line in cfg.get("preferred_ips") or []:
            parsed = parse_target_line(line)
            if parsed and parsed[2]:
                entries.append(parsed[2])
        if entries:
            shown = "、".join(entries[:8]) + ("…" if len(entries) > 8 else "")
            st.caption(f"当前优选列表里的入口节点：{shown}（这些是入口，不是出口）")

        if st.button("检测当前出口", key="check_exit"):
            with st.spinner("查询中…"):
                info, err = query_exit_ip(cfg)
            st.session_state[KEY_EXIT_RESULT] = (info, err)

        result = st.session_state.get(KEY_EXIT_RESULT)
        if not result:
            st.info("还没检测过。点上面的按钮查一次。")
            return

        info, err = result
        if err:
            st.error(f"检测失败：{err}")
            st.caption("两个查询接口都试过了。代理只放行特定端口、或者网络本身出不去，"
                       "都会失败 —— 这本身也是个有用的信号。")
            return

        c1, c2 = st.columns(2)
        c1.metric("出口 IP", info["ip"])
        c2.metric("归属地区", f"{info['country']}（{info['code']}）"
                  if info["code"] else info["country"])

        chain = build_outbound_chain(cfg)
        if chain:
            st.caption("链路：容器 → " + " → ".join(_describe_hop(p) for p in chain) + " → 目标")
            st.success("当前走代理链路，出口由落地节点决定。")
        else:
            st.caption("链路：容器 → 直连 → 目标")
            st.warning("当前是直连模式，出口就是容器的 IP。"
                       "换入口节点（香港 / 日本 / 美国…）不会改变它。"
                       "要换出口国家，去「落地与出站」把出站模式改成「走代理链路」，"
                       "并在落地节点里填目标国家的代理。")


def render_main_ui(secrets_cfg):
    """渲染主控制面板。"""
    st.set_page_config(page_title="部署工具", layout="wide")
    st.header("⚙️ 服务管理面板")

    # 回填必须在表单控件创建之前（控件一旦实例化，它的 session_state 键就锁住了），
    # 而它自己也会产生提示，所以顺序是：先回填 → 再统一显示提示。
    apply_pending_preferred_ips(secrets_cfg)
    render_flash()

    cfg = resolve_config(secrets_cfg)

    # 「优选 IP」文本框用 session_state 承载初值（不传 value=），
    # 否则 value 与 key 并存会触发 Streamlit 的冲突警告，测速结果也回填不进去。
    if KEY_PREFERRED_IPS not in st.session_state:
        st.session_state[KEY_PREFERRED_IPS] = "\n".join(cfg.get("preferred_ips") or [])

    st.subheader("控制操作")
    c1, c2, c3 = st.columns(3)

    if c1.button("🚀 强制重启服务", type="primary", use_container_width=True):
        # 手动点击按钮时，调用非静默模式，让用户看到反馈
        success, message = start_services(resolve_config(secrets_cfg), silent=False)
        st.session_state.output = message
        if success:
            set_flash("success", "✅ 服务已按当前配置重启。")
        else:
            set_flash("error", f"操作失败: {message}")
        st.rerun()

    if c2.button("❌ 永久卸载服务", use_container_width=True):
        with st.spinner("正在执行卸载..."):
            uninstall_services()
        # uninstall_services 会清空 session_state，所以提示要在它之后写入
        set_flash("success", "✅ 卸载完成。所有运行时文件和进程已清除。")
        st.rerun()

    if c3.button("📄 显示/刷新节点信息", use_container_width=True):
        if LIST_FILE.exists():
            st.session_state.output = LIST_FILE.read_text(encoding="utf-8")
        else:
            st.session_state.output = "节点信息文件不存在，请先启动服务。"
        st.rerun()

    # 优先从会话状态中读取输出，如果为空则尝试从文件读取
    output_to_show = st.session_state.get('output', '')
    if not output_to_show and LIST_FILE.exists():
        output_to_show = LIST_FILE.read_text(encoding="utf-8")

    if output_to_show:
        st.subheader("节点信息")
        st.code(output_to_show)

    # ---------- 配置区 ----------
    st.subheader("配置")
    st.caption("面板上改完点「保存并生效」，会自动重写 sing-box 配置并重启服务，无需改动 Secrets 或重新部署。")

    protocol_index = PROTOCOL_CHOICES.index(cfg.get("protocol")) if cfg.get("protocol") in PROTOCOL_CHOICES else 0

    with st.form("config_form"):
        tab_basic, tab_out, tab_node = st.tabs(["基础配置", "落地与出站", "优选节点"])

        with tab_basic:
            protocol = st.selectbox("协议", PROTOCOL_CHOICES, index=protocol_index)
            uuid_input = st.text_input("UUID", value=cfg.get("uuid_str") or "",
                                       help="留空会在首次启动时生成一个并固定下来")
            trojan_password = st.text_input("Trojan 密码", value=cfg.get("trojan_password") or "",
                                            type="password",
                                            help="仅协议选 trojan 时生效，留空则复用 UUID")
            ws_path = st.text_input("WebSocket 路径", value=cfg.get("ws_path") or "/")
            port_vm_ws = st.number_input("本地端口", min_value=0, max_value=65535,
                                         value=int(cfg.get("port_vm_ws") or 0),
                                         help="0 = 自动选择。该端口只在容器内部使用，不影响客户端。")
            custom_domain = st.text_input("自定义域名", value=cfg.get("custom_domain") or "",
                                          help="留空则使用 cloudflared 临时隧道域名（每次重启会变）")
            argo_token = st.text_input("Argo Token", value=cfg.get("argo_token") or "",
                                       type="password",
                                       help="填了就是固定隧道，域名不会变；留空走临时隧道")

        with tab_out:
            mode_label = st.radio("出站模式", ["直连（出口为容器 IP）", "走代理链路"],
                                  index=1 if str(cfg.get("outbound_mode")) == MODE_PROXY else 0,
                                  horizontal=True)
            hop1 = st.text_input("一级代理", value=cfg.get("hop1") or "",
                                 placeholder="socks5://user:pass@1.2.3.4:1080")
            hop2 = st.text_input("落地节点", value=cfg.get("hop2") or "",
                                 placeholder="socks5://user:pass@5.6.7.8:1080")
            st.caption("链路顺序：容器 → 一级代理 → 落地节点 → 目标。两级都可以留空；"
                       "只填落地节点时它会作为唯一一级出口使用。")

        with tab_node:
            preferred_ips_text = st.text_area(
                "优选 IP 列表（每行一条）",
                height=170,
                key=KEY_PREFERRED_IPS,
                placeholder="104.16.0.1\n104.17.0.1:8443\n[2606:4700::1]:443#香港",
                help="下面「在线优选测速」的结果可以直接回填到这里")
            preferred_domain = st.text_input("自定义优选域名",
                                             value=cfg.get("preferred_domain") or "",
                                             help="会作为一条节点追加在优选 IP 之后")

        submitted = st.form_submit_button("💾 保存并生效", type="primary", use_container_width=True)

    if submitted:
        new_cfg = {
            "protocol": protocol,
            "uuid_str": uuid_input.strip(),
            "trojan_password": trojan_password.strip(),
            "ws_path": normalize_path(ws_path),
            "port_vm_ws": int(port_vm_ws),
            "custom_domain": custom_domain.strip(),
            "argo_token": argo_token.strip(),
            "outbound_mode": MODE_PROXY if mode_label.startswith("走代理") else MODE_DIRECT,
            "hop1": hop1.strip(),
            "hop2": hop2.strip(),
            "preferred_ips": [line.strip() for line in preferred_ips_text.splitlines() if line.strip()],
            "preferred_domain": preferred_domain.strip(),
        }
        errors, warnings = validate_config(new_cfg)
        if errors:
            # 不保存、不重启 —— 宁可让用户改对，也不要静默忽略掉一个填错的落地地址
            st.error("保存失败，下面这些地方需要修正：")
            for item in errors:
                st.markdown(f"- {item}")
            st.info("正确写法：`socks5://用户名:密码@主机:端口` 或 `http://主机:端口`。"
                    "不带协议头时按 socks5 处理；用户名密码可以省略。")
        else:
            save_runtime_config(new_cfg)
            success, message = start_services(resolve_config(secrets_cfg), silent=False)
            st.session_state.output = message
            if success:
                flash_kind = "success"
                flash_text = "✅ 配置已保存并生效。"
            else:
                flash_kind = "error"
                flash_text = f"⚠️ 配置已保存，但重启失败: {message}"
            if warnings:
                flash_text += "\n\n" + "\n".join("· " + w for w in warnings)
                if flash_kind == "success":
                    flash_kind = "info"
            set_flash(flash_kind, flash_text)
            st.rerun()

    # ---------- 地区优选源（必须在 st.form 之外）----------
    render_region_sources(cfg)

    # ---------- 在线优选测速（必须在 st.form 之外）----------
    render_speed_test(cfg)

    # ---------- 出站链路测试（同样必须在 st.form 之外）----------
    render_outbound_test(cfg)

    # ---------- 出口 IP 检测（同样必须在 st.form 之外）----------
    render_exit_check(cfg)

    # ---------- 配置备份 ----------
    st.subheader("配置备份")
    st.caption("配置存在容器的 ~/.agsb/config.json 里。Streamlit Cloud 重新部署会清空容器，"
               "届时把导出的 JSON 传回来即可恢复。")
    b1, b2 = st.columns(2)
    with b1:
        st.download_button(
            "⬇️ 导出配置 JSON",
            data=json.dumps(resolve_config(secrets_cfg), ensure_ascii=False, indent=2),
            file_name="agsb-config.json",
            mime="application/json",
            use_container_width=True,
        )
    with b2:
        uploaded = st.file_uploader("⬆️ 导入配置 JSON", type=["json"],
                                    label_visibility="collapsed")

    if uploaded is not None:
        # 用文件名 + 大小做指纹，避免每次 rerun 重复导入
        fingerprint = f"{uploaded.name}:{uploaded.size}"
        if st.session_state.get("_last_import") != fingerprint:
            st.session_state["_last_import"] = fingerprint
            try:
                data = json.loads(uploaded.read().decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("配置内容不是一个 JSON 对象")
                clean = {k: v for k, v in data.items() if k in DEFAULT_CONFIG}
                if not clean:
                    raise ValueError("配置里没有可识别的字段")
                imported = {**DEFAULT_CONFIG, **clean}
                errors, _ = validate_config(imported)
                if errors:
                    raise ValueError("导入的配置里有问题：" + "；".join(errors))
                save_runtime_config(clean)
                # 让「优选 IP」文本框下次渲染时从新配置重新初始化
                st.session_state.pop(KEY_PREFERRED_IPS, None)
                st.session_state.pop(KEY_TEST_RESULTS, None)
                st.session_state.pop("_outbound_results", None)
                start_services(resolve_config(secrets_cfg), silent=True)
                set_flash("success", "✅ 配置已导入并重启服务。")
                st.rerun()
            except Exception as e:
                st.error(f"导入失败: {e}")


def render_login_ui(secret_key):
    """渲染伪装的天气查询登录界面。"""
    st.set_page_config(page_title="天气查询", layout="centered")
    st.title("🌦️ 实时天气查询")
    city = st.text_input("请输入城市名或秘密口令：", "")
    if st.button("查询天气"):
        if city == secret_key:
            st.session_state.authenticated = True
            st.rerun()
        else:
            with st.spinner(f"正在查询 {city} 的天气..."):
                time.sleep(1)
                st.error("查询失败，请检查城市名是否正确。")


def main():
    """主应用逻辑：先执行后台自愈，再根据登录状态渲染UI。"""
    st.session_state.setdefault('authenticated', False)
    st.session_state.setdefault('output', "")

    try:
        secret_key = st.secrets["SECRET_KEY"]
        secrets_cfg = {
            "uuid_str": st.secrets.get("UUID_STR", ""),
            "port_vm_ws": st.secrets.get("PORT_VM_WS", 0),
            "custom_domain": st.secrets.get("CUSTOM_DOMAIN", ""),
            "argo_token": st.secrets.get("ARGO_TOKEN", ""),
        }
    except (KeyError, FileNotFoundError, OSError):
        # KeyError：secrets 存在但缺少 SECRET_KEY
        # FileNotFoundError：完全没有配置 secrets（StreamlitSecretNotFoundError 继承自它）
        st.error("严重错误：未在 Secrets 中找到 'SECRET_KEY'。")
        st.info("请确保您已在 Streamlit Cloud 的设置中添加了名为 'SECRET_KEY' 的密钥。")
        return

    # --- 核心自愈逻辑 ---
    # 在渲染任何UI之前，先检查服务状态。如果服务未运行，就以“静默模式”在后台启动它。
    if not is_service_running():
        start_services(resolve_config(secrets_cfg), silent=True)

    # --- UI渲染逻辑 ---
    # 后台任务处理完毕后，才开始决定显示哪个页面
    if st.session_state.authenticated:
        # 如果已登录，显示主控制面板
        render_main_ui(secrets_cfg)
    else:
        # 如果未登录，显示伪装的天气查询页面
        render_login_ui(secret_key)


if __name__ == "__main__":
    main()
