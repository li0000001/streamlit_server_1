#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Streamlit + sing-box + cloudflared management panel (Linux)."""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import streamlit as st

ROOT = Path.home() / ".agsb"
CONFIG = ROOT / "config.json"
SB_CONFIG = ROOT / "sb.json"
STATE = ROOT / "processes.json"
NODES = ROOT / "allnodes.txt"
SB_LOG = ROOT / "sb.log"
CF_LOG = ROOT / "argo.log"
# Prefer installed binaries; optional automatic installation is intentionally omitted.
SB_BIN = ROOT / "sing-box"
CF_BIN = ROOT / "cloudflared"
DEFAULT = {
    "uuid_str": "", "port_vm_ws": 0, "custom_domain": "", "argo_token": "",
    "protocol": "vmess", "trojan_password": "", "ws_path": "/",
    "outbound_mode": "direct", "hop1": "", "hop2": "",
    "preferred_ips": [], "preferred_domain": "",
}
SECRET_KEYS = {"uuid_str": "UUID_STR", "port_vm_ws": "PORT_VM_WS",
               "custom_domain": "CUSTOM_DOMAIN", "argo_token": "ARGO_TOKEN"}
REGIONS = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡",
    "US": "美国", "KR": "韩国",
}
POOL_BASE = "https://bestcf.pages.dev/random-region/{}/100.txt"


def private_write(path, data):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    fd, temp = tempfile.mkstemp(dir=ROOT, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def read_json(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    private_write(CONFIG, json.dumps(cfg, ensure_ascii=False, indent=2))


def get_config():
    cfg = {**DEFAULT}
    for key, secret in SECRET_KEYS.items():
        try:
            value = st.secrets.get(secret)
        except (OSError, FileNotFoundError):
            value = None
        if value is not None:
            cfg[key] = value
    # Explicit empty strings in runtime config must override Secrets.
    cfg.update({k: v for k, v in read_json(CONFIG).items() if k in DEFAULT})
    return cfg


def ws_path(raw):
    return "/" + str(raw or "/").strip().lstrip("/")


def domain(raw):
    value = str(raw or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value
    ):
        raise ValueError("域名格式不正确，请只填写域名，不含 https:// 或路径")
    return value


def parse_proxy(raw):
    if not str(raw or "").strip():
        return None
    text = str(raw).strip()
    if "://" not in text:
        text = "socks5://" + text
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() not in ("socks5", "http") or not parsed.hostname:
        raise ValueError("代理仅支持 socks5:// 或 http://")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("代理端口无效") from exc
    if not port or not 1 <= port <= 65535 or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("代理格式应为 协议://用户名:密码@主机:端口")
    return {"type": "socks" if parsed.scheme.lower() == "socks5" else "http",
            "server": parsed.hostname, "server_port": port,
            "username": urllib.parse.unquote(parsed.username or ""),
            "password": urllib.parse.unquote(parsed.password or "")}


def validate(cfg):
    if cfg.get("protocol") not in ("vmess", "vless", "trojan"):
        raise ValueError("不支持的入站协议")
    if cfg.get("outbound_mode") not in ("direct", "proxy"):
        raise ValueError("不支持的出站模式")
    try:
        port = int(cfg.get("port_vm_ws") or 0)
    except (ValueError, TypeError) as exc:
        raise ValueError("本地端口必须是整数") from exc
    if not 0 <= port <= 65535:
        raise ValueError("本地端口超出范围")
    if cfg.get("uuid_str"):
        try:
            uuid.UUID(str(cfg["uuid_str"]))
        except ValueError as exc:
            raise ValueError("UUID 格式不正确") from exc
    if cfg.get("argo_token") and not cfg.get("custom_domain"):
        raise ValueError("固定隧道 Token 模式必须填写已配置路由的自定义域名")
    domain(cfg.get("custom_domain"))
    if cfg.get("preferred_domain"):
        domain(cfg["preferred_domain"])
    for field in ("hop1", "hop2"):
        try:
            parse_proxy(cfg.get(field))
        except ValueError as exc:
            raise ValueError(f"{field}: {exc}") from exc
    if cfg.get("outbound_mode") == "proxy" and not (cfg.get("hop1") or cfg.get("hop2")):
        raise ValueError("代理模式至少需要填写一级代理或落地节点")
    if not isinstance(cfg.get("preferred_ips"), list) or len(cfg["preferred_ips"]) > 500:
        raise ValueError("优选地址须为列表，最多 500 条")
    for entry in cfg["preferred_ips"]:
        if not parse_target(entry):
            raise ValueError(f"优选地址格式错误: {str(entry)[:80]}")
    if len(ws_path(cfg.get("ws_path"))) > 200:
        raise ValueError("WebSocket 路径过长")


def outbound(item, tag, detour=None):
    result = {"type": item["type"], "tag": tag, "server": item["server"],
              "server_port": item["server_port"]}
    if item["type"] == "socks":
        result["version"] = "5"
    if item["username"]:
        result["username"] = item["username"]
        result["password"] = item["password"]
    if detour:
        result["detour"] = detour
    return result


def singbox_config(cfg):
    protocol = cfg["protocol"]
    user = ({"password": cfg.get("trojan_password") or cfg["uuid_str"]}
            if protocol == "trojan" else {"uuid": cfg["uuid_str"]})
    if protocol == "vmess":
        user["alterId"] = 0
    if protocol == "vless":
        user["flow"] = ""
    inbound = {"type": protocol, "tag": "in", "listen": "127.0.0.1",
               "listen_port": int(cfg["port_vm_ws"]), "users": [user],
               "transport": {"type": "ws", "path": ws_path(cfg.get("ws_path"))}}
    first, second = parse_proxy(cfg.get("hop1")), parse_proxy(cfg.get("hop2"))
    outbounds = []
    if first:
        outbounds.append(outbound(first, "hop1"))
    if second:
        outbounds.append(outbound(second, "hop2", "hop1" if first else None))
    outbounds.append({"type": "direct", "tag": "direct"})
    final = "direct"
    if cfg["outbound_mode"] == "proxy":
        final = "hop2" if second else "hop1"
    return {"log": {"level": "info"}, "inbounds": [inbound],
            "outbounds": outbounds, "route": {"final": final}}


def parse_target(line):
    text = str(line or "").strip()
    if not text or text.startswith("#"):
        return None
    address, _, label = text.partition("#")
    address = address.strip()
    try:
        u = urllib.parse.urlsplit("//" + address)
        host, port = u.hostname, u.port or 443
        if not host or not 1 <= port <= 65535 or u.username or u.path or u.query:
            return None
        # Unbracketed IPv6 is permitted only without an explicit port.
        if ":" in address and not address.startswith("[") and address.count(":") > 1:
            host = str(ipaddress.IPv6Address(address))
            port = 443
        if any(c.isspace() for c in host):
            return None
        return host, port, label.strip()[:100]
    except (ValueError, AttributeError):
        try:
            return str(ipaddress.IPv6Address(address)), 443, label.strip()[:100]
        except ValueError:
            return None


def address(host, port):
    return f"[{host}]" + (f":{port}" if port != 443 else "") if ":" in host else host + (f":{port}" if port != 443 else "")


def make_links(hostname, cfg):
    targets, seen = [], set()
    for line in cfg["preferred_ips"]:
        parsed = parse_target(line)
        if parsed and parsed[:2] not in seen:
            seen.add(parsed[:2])
            targets.append((parsed[0], parsed[1], parsed[2] or "优选-" + parsed[0]))
    for host, name in ((cfg.get("preferred_domain"), "自定义域名"), (hostname, "隧道直连")):
        if host and (host, 443) not in seen:
            seen.add((host, 443))
            targets.append((host, 443, name))
    links = []
    for host, port, name in targets:
        q = urllib.parse.urlencode({"security": "tls", "sni": hostname, "type": "ws",
                                    "host": hostname, "path": ws_path(cfg["ws_path"])})
        if cfg["protocol"] == "vmess":
            obj = {"v": "2", "ps": name, "add": host, "port": str(port),
                   "id": cfg["uuid_str"], "aid": "0", "scy": "auto", "net": "ws",
                   "type": "none", "host": hostname, "path": ws_path(cfg["ws_path"]),
                   "tls": "tls", "sni": hostname}
            encoded = base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode().rstrip("=")
            links.append("vmess://" + encoded)
        else:
            credential = cfg["uuid_str"] if cfg["protocol"] == "vless" else cfg.get("trojan_password") or cfg["uuid_str"]
            if cfg["protocol"] == "vless":
                q = "encryption=none&" + q
            links.append(f"{cfg['protocol']}://{urllib.parse.quote(credential, safe='')}@{address(host, port)}?{q}#{urllib.parse.quote(name)}")
    return links


def proc_identity(pid, binary):
    """Linux-only: verify executable path, UID and non-zombie status before signal."""
    try:
        pid = int(pid)
        if pid < 1:
            return False
        proc = Path("/proc") / str(pid)
        exe = (proc / "exe").resolve(strict=True)
        expected = binary.resolve(strict=True)
        uid = (proc / "status").read_text().split("Uid:", 1)[1].split()[0]
        state = (proc / "status").read_text().split("State:", 1)[1].split()[0]
        return exe == expected and int(uid) == os.getuid() and state != "Z"
    except (OSError, ValueError, IndexError):
        return False


def stop_services():
    records = read_json(STATE)
    for label, binary in (("cloudflared", CF_BIN), ("sing-box", SB_BIN)):
        pid = records.get(label)
        if proc_identity(pid, binary):
            try:
                os.kill(int(pid), 15)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and any(proc_identity(records.get(k), b) for k, b in
            (("cloudflared", CF_BIN), ("sing-box", SB_BIN))):
        time.sleep(.1)
    for label, binary in (("cloudflared", CF_BIN), ("sing-box", SB_BIN)):
        pid = records.get(label)
        if proc_identity(pid, binary):
            try:
                os.kill(int(pid), 9)
            except ProcessLookupError:
                pass
    STATE.unlink(missing_ok=True)


def running():
    pids = read_json(STATE)
    return proc_identity(pids.get("sing-box"), SB_BIN) and proc_identity(pids.get("cloudflared"), CF_BIN)


def log_tail(path, length=2500):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-length:]
    except OSError:
        return "（无日志）"


def local_ready(port, process, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError("sing-box 提前退出: " + log_tail(SB_LOG))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.5):
                return
        except OSError:
            time.sleep(.2)
    raise RuntimeError("本地监听端口未就绪: " + log_tail(SB_LOG))


def quick_domain(process, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError("cloudflared 提前退出: " + log_tail(CF_LOG))
        match = re.search(r"https://([a-z0-9-]+\.trycloudflare\.com)", log_tail(CF_LOG, 10000))
        if match:
            return match.group(1)
        time.sleep(.5)
    raise RuntimeError("未从隧道日志获取临时域名: " + log_tail(CF_LOG))


def pick_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_services(cfg):
    """Check local service and tunnel process; external end-to-end reachability is not guaranteed."""
    validate(cfg)
    if platform.system() != "Linux":
        raise RuntimeError("当前版本只支持 Linux")
    for binary in (SB_BIN, CF_BIN):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"缺少可执行文件: {binary}；请先从官方发行版安装到该路径")
    stop_services()
    cfg = dict(cfg)
    if not cfg.get("uuid_str"):
        cfg["uuid_str"] = str(uuid.uuid4())
    if not cfg.get("port_vm_ws"):
        cfg["port_vm_ws"] = pick_port()
    # Persist generated values without resetting any other configured fields.
    saved = read_json(CONFIG)
    saved.update({"uuid_str": cfg["uuid_str"], "port_vm_ws": cfg["port_vm_ws"]})
    save_config(saved)
    private_write(SB_CONFIG, json.dumps(singbox_config(cfg), ensure_ascii=False, indent=2))
    check = subprocess.run([str(SB_BIN), "check", "-c", str(SB_CONFIG)],
                           cwd=ROOT, capture_output=True, text=True, timeout=20)
    if check.returncode:
        raise RuntimeError("sing-box 配置检查失败: " + (check.stderr or check.stdout)[-1500:])
    sb = cf = None
    try:
        with SB_LOG.open("w") as log:
            sb = subprocess.Popen([str(SB_BIN), "run", "-c", str(SB_CONFIG)],
                                  cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        local_ready(int(cfg["port_vm_ws"]), sb)
        if cfg.get("argo_token"):
            command = [str(CF_BIN), "tunnel", "--no-autoupdate", "run", "--token", cfg["argo_token"]]
        else:
            command = [str(CF_BIN), "tunnel", "--no-autoupdate", "--url",
                       f"http://127.0.0.1:{cfg['port_vm_ws']}", "--protocol", "http2"]
        with CF_LOG.open("w") as log:
            cf = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        hostname = domain(cfg.get("custom_domain")) if cfg.get("argo_token") else quick_domain(cf)
        if cf.poll() is not None:
            raise RuntimeError("cloudflared 提前退出: " + log_tail(CF_LOG))
        private_write(STATE, json.dumps({"sing-box": sb.pid, "cloudflared": cf.pid}))
        links = make_links(hostname, cfg)
        private_write(NODES, "\n".join(links) + "\n")
        return hostname, links
    except Exception:
        for proc in (cf, sb):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        STATE.unlink(missing_ok=True)
        raise


def tcp_ms(host, port):
    begin = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=2):
            return round((time.perf_counter() - begin) * 1000)
    except OSError:
        return None


def get_pool(code, count):
    url = POOL_BASE.format(code)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as response:
        text = response.read(300000).decode("utf-8", "replace")
    items = []
    for line in text.splitlines():
        match = re.search(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?", line)
        if not match:
            continue
        try:
            ipaddress.IPv4Address(match.group(1))
            port = int(match.group(2) or 443)
            if not 1 <= port <= 65535:
                continue
        except ValueError:
            continue
        items.append((match.group(1), port))
        if len(items) >= count:
            break
    return items


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise OSError("代理提前断开")
        buf += part
    return buf


def dial_chain(chain, host, port):
    if not chain:
        return socket.create_connection((host, port), timeout=8)
    sock = socket.create_connection((chain[0]["server"], chain[0]["server_port"]), timeout=8)
    sock.settimeout(8)
    try:
        for i, hop in enumerate(chain):
            target = chain[i + 1] if i + 1 < len(chain) else {"server": host, "server_port": port}
            h, p = target["server"], target["server_port"]
            if hop["type"] == "http":
                credentials = ""
                if hop["username"]:
                    token = base64.b64encode((hop["username"] + ":" + hop["password"]).encode()).decode()
                    credentials = f"Proxy-Authorization: Basic {token}\r\n"
                authority = address(h, p)
                sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{credentials}\r\n".encode())
                response = http.client.HTTPResponse(sock)
                response.begin()
                if response.status != 200:
                    raise OSError(f"HTTP CONNECT 返回 {response.status}")
            else:
                methods = b"\x00\x02" if hop["username"] else b"\x00"
                sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
                version, method = recv_exact(sock, 2)
                if version != 5 or method == 255:
                    raise OSError("SOCKS5 协商失败")
                if method == 2:
                    user, pwd = hop["username"].encode(), hop["password"].encode()
                    if len(user) > 255 or len(pwd) > 255:
                        raise OSError("SOCKS5 凭据过长")
                    sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
                    if recv_exact(sock, 2) != b"\x01\x00":
                        raise OSError("SOCKS5 认证失败")
                elif method != 0:
                    raise OSError("SOCKS5 认证方式不支持")
                try:
                    ip = ipaddress.ip_address(h)
                    dest = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
                except ValueError:
                    hb = h.encode("idna")
                    if len(hb) > 255:
                        raise OSError("域名过长")
                    dest = b"\x03" + bytes([len(hb)]) + hb
                sock.sendall(b"\x05\x01\x00" + dest + p.to_bytes(2, "big"))
                reply = recv_exact(sock, 4)
                if reply[1] != 0:
                    raise OSError(f"SOCKS5 CONNECT 失败: {reply[1]}")
                atyp = reply[3]
                if atyp == 3:
                    recv_exact(sock, recv_exact(sock, 1)[0])
                elif atyp in (1, 4):
                    recv_exact(sock, 4 if atyp == 1 else 16)
                else:
                    raise OSError("SOCKS5 地址类型错误")
                recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def exit_ip(cfg):
    chain = [] if cfg["outbound_mode"] == "direct" else [parse_proxy(cfg.get(k)) for k in ("hop1", "hop2")]
    chain = [x for x in chain if x]
    host = "api.country.is"
    raw = dial_chain(chain, host, 443)
    with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as sock:
        sock.settimeout(8)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(sock)
        response.begin()
        if response.status != 200:
            raise OSError(f"出口查询返回 HTTP {response.status}")
        data = json.loads(response.read(65536))
        return data.get("ip", "未知"), data.get("country", "未知")


def merge_entries(current, additions):
    lines = [x.strip() for x in current.splitlines() if x.strip()]
    seen = {p[:2] for x in lines if (p := parse_target(x))}
    for entry in additions:
        parsed = parse_target(entry)
        if parsed and parsed[:2] not in seen:
            seen.add(parsed[:2])
            lines.append(entry)
    return "\n".join(lines)


def panel():
    st.title("服务管理面板")
    cfg = get_config()
    if "ips_editor" not in st.session_state:
        st.session_state.ips_editor = "\n".join(cfg["preferred_ips"])
    if "pending_ips" in st.session_state:
        st.session_state.ips_editor = merge_entries(st.session_state.ips_editor, st.session_state.pop("pending_ips"))
        st.info("地址已加入输入框，请点击「保存并生效」。")
    st.caption("服务仅在登录后操作；关闭网页不会自动停止已启动的进程。")
    st.write("运行状态：", "运行中" if running() else "未运行")
    c1, c2, c3 = st.columns(3)
    if c1.button("启动 / 重启", use_container_width=True):
        try:
            hostname, links = start_services(cfg)
            st.success(f"本地服务已就绪，隧道进程正在运行：{hostname}")
            st.session_state.links = links
        except Exception as exc:
            st.error(str(exc))
    if c2.button("停止服务", use_container_width=True):
        stop_services()
        st.success("已停止本项目记录的服务进程")
    if c3.button("卸载运行文件", use_container_width=True):
        stop_services()
        shutil.rmtree(ROOT, ignore_errors=True)
        st.session_state.clear()
        st.rerun()
    if NODES.exists():
        st.subheader("节点链接")
        st.code(NODES.read_text(encoding="utf-8"))
        st.caption("链接包含连接凭据，请勿公开分享。")
    with st.expander("配置", expanded=True):
        with st.form("config_form"):
            basic, proxy_tab, targets_tab = st.tabs(["基础配置", "落地与出站", "优选节点"])
            with basic:
                proto = st.selectbox("协议", ["vmess", "vless", "trojan"],
                                     index=["vmess", "vless", "trojan"].index(cfg["protocol"]))
                user_id = st.text_input("UUID", cfg["uuid_str"], help="留空时首次启动生成")
                password = st.text_input("Trojan 密码", cfg["trojan_password"], type="password")
                path = st.text_input("WebSocket 路径", cfg["ws_path"])
                port = st.number_input("本地端口（0 自动分配）", 0, 65535, int(cfg["port_vm_ws"]))
                hostname = st.text_input("固定隧道域名", cfg["custom_domain"])
                token = st.text_input("Cloudflare Tunnel Token", cfg["argo_token"], type="password")
            with proxy_tab:
                mode = st.radio("出站", ["direct", "proxy"], index=int(cfg["outbound_mode"] == "proxy"))
                hop1 = st.text_input("一级代理", cfg["hop1"], type="password")
                hop2 = st.text_input("落地节点", cfg["hop2"], type="password")
                st.caption("支持 socks5:// 和 http://；带特殊字符的账号密码请先 URL 编码。")
            with targets_tab:
                ips = st.text_area("优选地址（每行一条，可加 #名称）", key="ips_editor", height=180)
                preferred_domain = st.text_input("自定义优选域名", cfg["preferred_domain"])
            submitted = st.form_submit_button("保存并生效")
        if submitted:
            new = {"protocol": proto, "uuid_str": user_id.strip(),
                   "trojan_password": password, "ws_path": ws_path(path),
                   "port_vm_ws": int(port), "custom_domain": hostname.strip(),
                   "argo_token": token.strip(), "outbound_mode": mode,
                   "hop1": hop1.strip(), "hop2": hop2.strip(),
                   "preferred_ips": [x.strip() for x in ips.splitlines() if x.strip()],
                   "preferred_domain": preferred_domain.strip()}
            try:
                validate(new)
                save_config(new)
                hostname, links = start_services(get_config())
                st.success(f"配置已保存，本地服务已就绪：{hostname}")
            except Exception as exc:
                st.error(f"保存或启动失败：{exc}")
    with st.expander("地区优选源"):
        selected = st.multiselect("地区", list(REGIONS), default=["HK"],
                                  format_func=lambda x: f"{REGIONS[x]} ({x})")
        count = st.number_input("每个地区数量", 1, 100, 10)
        if st.button("拉取并加入输入框"):
            additions, errors = [], []
            for code in selected:
                try:
                    for i, (host, p) in enumerate(get_pool(code, int(count)), 1):
                        additions.append(f"{address(host, p)}#{REGIONS[code]}-{i:02d}")
                except Exception as exc:
                    errors.append(f"{code}: {exc}")
            st.session_state.pending_ips = additions
            if errors:
                st.warning("；".join(errors))
            if additions:
                st.rerun()
    with st.expander("TCP 优选测速"):
        text = st.text_area("待测地址", key="test_input")
        if st.button("开始测速"):
            targets = list(dict.fromkeys((p[0], p[1]) for line in text.splitlines()
                                             if (p := parse_target(line))))[:200]
            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = {pool.submit(tcp_ms, h, p): (h, p) for h, p in targets}
                rows = [(h, p, future.result()) for future, (h, p) in
                        ((f, futures[f]) for f in as_completed(futures))]
            st.session_state.test_results = sorted((r for r in rows if r[2] is not None), key=lambda x: x[2])
        results = st.session_state.get("test_results", [])
        if results:
            st.dataframe([{"地址": address(h, p), "延迟(ms)": ms} for h, p, ms in results])
            n = st.number_input("加入前 N 个", 1, len(results), min(10, len(results)))
            if st.button("加入优选输入框"):
                st.session_state.pending_ips = [f"{address(h, p)}#测速{ms}ms" for h, p, ms in results[:int(n)]]
                st.rerun()
    with st.expander("出口 IP 检测"):
        st.caption("检测按已保存的出站配置建立代理链，不代表客户端至隧道的端到端连通性。")
        if st.button("检测当前出口"):
            try:
                ip, country = exit_ip(get_config())
                st.success(f"出口 IP：{ip}；地区代码：{country}")
            except Exception as exc:
                st.error(f"检测失败：{exc}")
    with st.expander("备份与日志"):
        st.download_button("导出配置 JSON（含敏感凭据）", json.dumps(get_config(), ensure_ascii=False, indent=2),
                           file_name="agsb-config.json", mime="application/json")
        upload = st.file_uploader("导入配置 JSON", type="json")
        if upload is not None and st.button("确认导入并重启"):
            try:
                data = json.loads(upload.getvalue().decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("需要 JSON 对象")
                imported = {**DEFAULT, **{k: v for k, v in data.items() if k in DEFAULT}}
                validate(imported)
                save_config(imported)
                st.session_state.pop("ips_editor", None)
                start_services(get_config())
                st.success("导入成功，服务已重启")
                st.rerun()
            except Exception as exc:
                st.error(f"导入失败：{exc}")
        st.text_area("sing-box 日志", log_tail(SB_LOG), height=140)
        st.text_area("cloudflared 日志", log_tail(CF_LOG), height=140)


def main():
    st.set_page_config(page_title="服务管理面板", layout="wide")
    if platform.system() != "Linux":
        st.error("此版本仅支持 Linux")
        return
    try:
        secret = str(st.secrets["SECRET_KEY"])
    except (KeyError, OSError, FileNotFoundError):
        st.error("请先在 Streamlit Secrets 中配置 SECRET_KEY")
        return
    if not secret:
        st.error("SECRET_KEY 不得为空")
        return
    if not st.session_state.get("authenticated", False):
        st.title("服务管理登录")
        entered = st.text_input("访问口令", type="password")
        if st.button("登录"):
            if hmac.compare_digest(entered, secret):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("口令错误")
        return
    if st.sidebar.button("退出登录"):
        st.session_state.authenticated = False
        st.rerun()
    panel()


if __name__ == "__main__":
    main()
