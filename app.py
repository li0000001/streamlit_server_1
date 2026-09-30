#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Streamlit sing-box / cloudflared management panel.

Requires Streamlit and SECRET_KEY in Streamlit Secrets. Start services explicitly
from the authenticated panel; the app never downloads binaries before rendering.
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote, unquote, urlencode, urlsplit

import streamlit as st

ROOT = Path.home() / ".agsb"
CONFIG = ROOT / "config.json"
SB_CONFIG = ROOT / "sb.json"
SB_LOG = ROOT / "sb.log"
CF_LOG = ROOT / "argo.log"
SB_PID = ROOT / "sbpid.log"
CF_PID = ROOT / "sbargopid.log"
NODES = ROOT / "allnodes.txt"
SB_BIN = ROOT / "sing-box"
CF_BIN = ROOT / "cloudflared"
DEFAULT = dict(uuid_str="", port_vm_ws=0, custom_domain="", argo_token="",
               protocol="vmess", trojan_password="", ws_path="/",
               outbound_mode="direct", hop1="", hop2="", preferred_ips=[],
               preferred_domain="")
REGIONS = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡",
    "US": "美国", "KR": "韩国",
}
REGION_URL = "https://bestcf.pages.dev/random-region/{}/100.txt"


def load_config():
    try:
        value = json.loads(CONFIG.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    ROOT.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        CONFIG.chmod(0o600)
    except OSError:
        pass


def effective_config(secrets=None):
    cfg = DEFAULT.copy()
    for src in (secrets or {}, load_config()):
        for key, value in src.items():
            if key in DEFAULT and value not in (None, ""):
                cfg[key] = value
    return cfg


def parse_proxy_url(raw):
    """Supported: socks5://user:pass@host:port, http://user:pass@host:port."""
    raw = str(raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "socks5://" + raw
    try:
        u = urlsplit(raw)
        if u.scheme.lower() not in ("socks5", "socks", "http") or not u.hostname:
            raise ValueError("仅支持 socks5、socks、http")
        if u.path or u.query or u.fragment or not u.port or not 0 < u.port < 65536:
            raise ValueError("地址或端口不正确")
        return {"type": "http" if u.scheme.lower() == "http" else "socks",
                "server": u.hostname, "server_port": u.port,
                "username": unquote(u.username or ""),
                "password": unquote(u.password or "")}
    except ValueError as exc:
        raise ValueError("代理地址格式错误（只支持 socks5:// 或 http://）：" + str(exc)) from exc


def validate(cfg):
    if cfg.get("protocol") not in ("vmess", "vless", "trojan"):
        raise ValueError("不支持的入站协议")
    try:
        port = int(cfg.get("port_vm_ws") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("本地端口必须是数字") from exc
    if not 0 <= port <= 65535:
        raise ValueError("本地端口超出范围")
    if cfg.get("uuid_str"):
        try:
            uuid.UUID(str(cfg["uuid_str"]))
        except ValueError as exc:
            raise ValueError("UUID 格式错误") from exc
    for field in ("hop1", "hop2"):
        if str(cfg.get(field) or "").strip():
            parse_proxy_url(cfg[field])
    if cfg.get("outbound_mode") not in ("direct", "proxy"):
        raise ValueError("出站模式错误")
    if cfg["outbound_mode"] == "proxy" and not any(str(cfg.get(k) or "").strip() for k in ("hop1", "hop2")):
        raise ValueError("代理模式必须至少配置一级代理或落地节点，禁止回退直连")
    if cfg.get("argo_token") and not cfg.get("custom_domain"):
        raise ValueError("固定 Tunnel Token 需要同时填写自定义域名")
    return cfg


def normalize_path(path):
    return "/" + str(path or "/").strip().lstrip("/")


def outbound(parsed, tag, detour=None):
    obj = {"type": parsed["type"], "tag": tag,
           "server": parsed["server"], "server_port": parsed["server_port"]}
    if parsed["type"] == "socks":
        obj["version"] = "5"
    for k in ("username", "password"):
        if parsed[k]:
            obj[k] = parsed[k]
    if detour:
        obj["detour"] = detour
    return obj


def build_singbox_config(cfg):
    validate(cfg)
    proto = cfg["protocol"]
    inbound = {"type": proto, "tag": "in", "listen": "127.0.0.1",
               "listen_port": int(cfg["port_vm_ws"]),
               "transport": {"type": "ws", "path": normalize_path(cfg["ws_path"])}}
    if proto == "trojan":
        inbound["users"] = [{"password": cfg.get("trojan_password") or cfg["uuid_str"]}]
    elif proto == "vless":
        inbound["users"] = [{"uuid": cfg["uuid_str"]}]
    else:
        inbound["users"] = [{"uuid": cfg["uuid_str"], "alterId": 0}]
    outs = []
    h1, h2 = (parse_proxy_url(cfg.get(k)) for k in ("hop1", "hop2"))
    if cfg["outbound_mode"] == "proxy":
        if h1:
            outs.append(outbound(h1, "hop1"))
        if h2:
            outs.append(outbound(h2, "hop2", "hop1" if h1 else None))
        final = "hop2" if h2 else "hop1"
    else:
        final = "direct"
    outs.append({"type": "direct", "tag": "direct"})
    return {"log": {"level": "info"}, "inbounds": [inbound],
            "outbounds": outs, "route": {"final": final}}


def proc_identity(pid, binary):
    try:
        if isinstance(pid, bool):
            return False
        pid = int(pid)
        if pid <= 0:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, ValueError, OSError):
        return False
    except PermissionError:
        return False
    if platform.system() == "Linux":
        try:
            actual = (Path("/proc") / str(pid) / "exe").resolve(strict=True)
            return actual == Path(binary).resolve(strict=True)
        except OSError:
            return False
    return True


def pid_from_file(path):
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError, TypeError):
        return None


def running():
    return proc_identity(pid_from_file(SB_PID), SB_BIN) and proc_identity(pid_from_file(CF_PID), CF_BIN)


def stop_services():
    for pidfile, binary in ((SB_PID, SB_BIN), (CF_PID, CF_BIN)):
        pid = pid_from_file(pidfile)
        if proc_identity(pid, binary):
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        pidfile.unlink(missing_ok=True)


def _download(url, dest, limit=120_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    temp = dest.with_suffix(".download")
    try:
        with urllib.request.urlopen(req, timeout=30) as src, temp.open("wb") as out:
            count = 0
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > limit:
                    raise ValueError("下载文件过大")
                out.write(chunk)
        temp.replace(dest)
    finally:
        temp.unlink(missing_ok=True)


def install_binaries():
    ROOT.mkdir(parents=True, exist_ok=True)
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch, cf_arch = "amd64", "amd64"
    elif machine in ("aarch64", "arm64"):
        arch, cf_arch = "arm64", "arm64"
    else:
        raise RuntimeError("不支持的 CPU 架构：" + machine)
    if not SB_BIN.exists():
        version = "1.9.0-beta.11"  # Keep the version used by the supplied project.
        folder = f"sing-box-{version}-linux-{arch}"
        archive = ROOT / "sing-box.tar.gz"
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{folder}.tar.gz"
        _download(url, archive)
        with tarfile.open(archive, "r:gz") as tar:
            member = next((m for m in tar.getmembers()
                           if m.name == folder + "/sing-box" and m.isfile()), None)
            if member is None:
                raise RuntimeError("sing-box 压缩包缺少预期文件")
            with tar.extractfile(member) as src, SB_BIN.open("wb") as out:
                shutil.copyfileobj(src, out)
        archive.unlink(missing_ok=True)
        SB_BIN.chmod(0o755)
    if not CF_BIN.exists():
        _download(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", CF_BIN)
        CF_BIN.chmod(0o755)


def parse_target_line(line, default_port=443):
    raw, _, name = str(line).strip().partition("#")
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("["):
        m = re.fullmatch(r"\[([^]]+)\](?::(\d+))?", raw)
        if not m:
            return None
        host, port = m[1], int(m[2] or default_port)
    elif raw.count(":") == 1:
        host, p = raw.rsplit(":", 1)
        if not p.isdigit():
            return None
        port = int(p)
    else:
        host, port = raw, int(default_port)
    return (host, port, name.strip()) if host and 0 < port < 65536 else None


def format_target(host, port):
    host = "[" + host + "]" if ":" in host and not host.startswith("[") else host
    return host if port == 443 else f"{host}:{port}"


def build_node_links(domain, cfg):
    if not domain:
        return []
    targets, seen = [], set()
    for line in cfg.get("preferred_ips") or []:
        item = parse_target_line(line)
        if item and item[:2] not in seen:
            seen.add(item[:2])
            targets.append(item)
    for host, name in ((cfg.get("preferred_domain", "").strip(), "自定义域名"),
                       (domain, "隧道直连")):
        if host and (host, 443) not in seen:
            targets.append((host, 443, name))
            seen.add((host, 443))
    links = []
    for host, port, name in targets:
        name = name or "优选-" + host
        query = urlencode({"security": "tls", "sni": domain, "type": "ws",
                           "host": domain, "path": normalize_path(cfg["ws_path"])})
        authority = format_target(host, port) if port != 443 else format_target(host, 443) + ":443"
        if cfg["protocol"] == "vmess":
            obj = {"v": "2", "ps": name, "add": host, "port": str(port),
                   "id": cfg["uuid_str"], "aid": "0", "scy": "auto", "net": "ws",
                   "type": "none", "host": domain, "path": normalize_path(cfg["ws_path"]),
                   "tls": "tls", "sni": domain}
            links.append("vmess://" + base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode().rstrip("="))
        elif cfg["protocol"] == "vless":
            links.append(f"vless://{cfg['uuid_str']}@{authority}?encryption=none&{query}#{quote(name)}")
        else:
            pw = cfg.get("trojan_password") or cfg["uuid_str"]
            links.append(f"trojan://{quote(pw, safe='')}@{authority}?{query}#{quote(name)}")
    return links


def get_tunnel_domain(timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if CF_LOG.exists():
            text = CF_LOG.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"https://([a-zA-Z0-9.-]+\.trycloudflare\.com)", text)
            if m:
                return m.group(1)
        time.sleep(1)
    return ""


def start_services(cfg):
    """Called only from an authenticated button; never on initial page load."""
    cfg = dict(cfg)
    validate(cfg)
    ROOT.mkdir(parents=True, exist_ok=True)
    if not cfg.get("uuid_str"):
        cfg["uuid_str"] = str(uuid.uuid4())
    if not int(cfg.get("port_vm_ws") or 0):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cfg["port_vm_ws"] = sock.getsockname()[1]
    validate(cfg)
    install_binaries()
    generated = build_singbox_config(cfg)
    SB_CONFIG.write_text(json.dumps(generated, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        SB_CONFIG.chmod(0o600)
    except OSError:
        pass
    check = subprocess.run([str(SB_BIN), "check", "-c", str(SB_CONFIG)],
                           capture_output=True, text=True, timeout=15)
    if check.returncode:
        raise RuntimeError("sing-box 配置校验失败：" + (check.stderr or check.stdout)[-800:])
    stop_services()
    try:
        with SB_LOG.open("w") as sb_out, CF_LOG.open("w") as cf_out:
            sb = subprocess.Popen([str(SB_BIN), "run", "-c", str(SB_CONFIG)],
                                  cwd=ROOT, stdout=sb_out, stderr=subprocess.STDOUT)
            SB_PID.write_text(str(sb.pid), encoding="utf-8")
            if cfg.get("argo_token"):
                cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "run", "--token", cfg["argo_token"]]
            else:
                cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "--url",
                       f"http://127.0.0.1:{cfg['port_vm_ws']}", "--protocol", "http2"]
            cf = subprocess.Popen(cmd, cwd=ROOT, stdout=cf_out, stderr=subprocess.STDOUT)
            CF_PID.write_text(str(cf.pid), encoding="utf-8")
        time.sleep(1)
        if sb.poll() is not None or cf.poll() is not None:
            raise RuntimeError("服务进程提前退出，请查看 sing-box / cloudflared 日志")
        domain = cfg.get("custom_domain") or get_tunnel_domain()
        if not domain:
            raise RuntimeError("未获取到隧道域名，请查看 cloudflared 日志")
        links = build_node_links(domain, cfg)
        NODES.write_text("\n".join(links) + "\n", encoding="utf-8")
        save_config(cfg)
        return domain, links
    except Exception:
        stop_services()
        raise


def _read_exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise OSError("代理提前断开连接")
        result += part
    return result


def _connect_via_proxy(sock, proxy, host, port):
    if proxy["type"] == "http":
        address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        headers = f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n"
        if proxy["username"]:
            credential = base64.b64encode((proxy["username"] + ":" + proxy["password"]).encode()).decode()
            headers += f"Proxy-Authorization: Basic {credential}\r\n"
        sock.sendall((headers + "\r\n").encode("ascii"))
        head = b""
        while not head.endswith(b"\r\n\r\n") and len(head) < 8192:
            head += _read_exact(sock, 1)
        if not re.match(rb"HTTP/\d(?:\.\d)? 200(?:\s|\r)", head):
            raise OSError("HTTP CONNECT 失败：" + head.split(b"\r\n")[0].decode("latin-1"))
        return
    user, password = proxy["username"], proxy["password"]
    sock.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    method = _read_exact(sock, 2)
    if method[0] != 5 or method[1] == 255:
        raise OSError("SOCKS5 协商失败")
    if method[1] == 2:
        ub, pb = user.encode(), password.encode()
        if not user or max(len(ub), len(pb)) > 255:
            raise OSError("SOCKS5 账号密码无效")
        sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        if _read_exact(sock, 2) != b"\x01\x00":
            raise OSError("SOCKS5 认证失败")
    elif method[1] != 0:
        raise OSError("不支持的 SOCKS5 认证方式")
    try:
        ip = ipaddress.ip_address(host)
        address = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise OSError("目标域名太长")
        address = b"\x03" + bytes([len(encoded)]) + encoded
    sock.sendall(b"\x05\x01\x00" + address + int(port).to_bytes(2, "big"))
    resp = _read_exact(sock, 4)
    if resp[1] != 0:
        raise OSError(f"SOCKS5 CONNECT 失败：{resp[1]}")
    if resp[3] == 1:
        _read_exact(sock, 4)
    elif resp[3] == 4:
        _read_exact(sock, 16)
    elif resp[3] == 3:
        _read_exact(sock, _read_exact(sock, 1)[0])
    else:
        raise OSError("SOCKS5 响应地址类型无效")
    _read_exact(sock, 2)


def build_outbound_chain(cfg):
    if cfg.get("outbound_mode") != "proxy":
        return []
    validate(cfg)
    return [parse_proxy_url(cfg[k]) for k in ("hop1", "hop2") if str(cfg.get(k) or "").strip()]


def query_exit_ip(cfg, timeout=8):
    """Panel check uses the same hop order; failure never falls back to direct."""
    chain = build_outbound_chain(cfg)
    host = "api.country.is"
    sock = None
    try:
        first = chain[0]["server"] if chain else host
        first_port = chain[0]["server_port"] if chain else 443
        sock = socket.create_connection((first, first_port), timeout=timeout)
        sock.settimeout(timeout)
        for index, proxy in enumerate(chain):
            next_hop = chain[index + 1] if index + 1 < len(chain) else None
            target_host = next_hop["server"] if next_hop else host
            target_port = next_hop["server_port"] if next_hop else 443
            _connect_via_proxy(sock, proxy, target_host, target_port)
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(sock)
        response.begin()
        if response.status != 200:
            raise OSError(f"查询接口 HTTP {response.status}")
        payload = json.loads(response.read(65536))
        ip = payload.get("ip")
        if not ip:
            raise ValueError("查询接口未返回 IP")
        return {"ip": ip, "country": payload.get("country", ""),
                "via": " → ".join(["容器"] + [f"{p['server']}:{p['server_port']}" for p in chain] + ["目标"])}, ""
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()


def latency(host, port, timeout=2):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.perf_counter() - start) * 1000)
    except OSError:
        return None


def fetch_region_pool(code, limit=10):
    req = urllib.request.Request(REGION_URL.format(code), headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as response:
        text = response.read(250000).decode("utf-8", "ignore")
    out, seen = [], set()
    for line in text.splitlines():
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?", line)
        if not m:
            continue
        try:
            ipaddress.IPv4Address(m[1])
            port = int(m[2] or 443)
        except ValueError:
            continue
        if not 0 < port < 65536 or (m[1], port) in seen:
            continue
        seen.add((m[1], port))
        out.append((m[1], port))
        if len(out) >= limit:
            break
    return out


def append_preferred(entries, cfg):
    existing = list(cfg.get("preferred_ips") or [])
    seen = {p[:2] for line in existing if (p := parse_target_line(line))}
    added = 0
    for host, port, name in entries:
        if (host, port) in seen:
            continue
        existing.append(format_target(host, port) + ("#" + name if name else ""))
        seen.add((host, port))
        added += 1
    cfg["preferred_ips"] = existing
    save_config(cfg)
    return added


def render_panel(secrets_cfg):
    st.header("⚙️ 服务管理面板")
    cfg = effective_config(secrets_cfg)
    st.write("运行状态：", "运行中" if running() else "未运行")
    st.caption("页面不会自动下载或启动后台服务；登录后使用下方按钮启动。")
    with st.form("settings"):
        t1, t2, t3 = st.tabs(["基础配置", "落地与出站", "优选节点"])
        with t1:
            proto = st.selectbox("协议", ["vmess", "vless", "trojan"],
                                 index=["vmess", "vless", "trojan"].index(cfg["protocol"])
                                 if cfg["protocol"] in ("vmess", "vless", "trojan") else 0)
            user_id = st.text_input("UUID", value=cfg["uuid_str"])
            trojan_pw = st.text_input("Trojan 密码", value=cfg["trojan_password"], type="password")
            ws_path = st.text_input("WebSocket 路径", value=cfg["ws_path"])
            port = st.number_input("本地端口（0 = 自动）", 0, 65535, int(cfg["port_vm_ws"] or 0))
            domain = st.text_input("自定义域名", value=cfg["custom_domain"])
            token = st.text_input("Argo Token", value=cfg["argo_token"], type="password")
        with t2:
            mode = st.radio("出站模式", ["direct", "proxy"],
                            index=1 if cfg["outbound_mode"] == "proxy" else 0,
                            format_func=lambda x: "走代理链路" if x == "proxy" else "直连")
            hop1 = st.text_input("一级代理", value=cfg["hop1"], type="password")
            hop2 = st.text_input("落地节点", value=cfg["hop2"], type="password")
            st.caption("容器 → 一级代理 → 落地节点 → 目标；仅填写一个节点也可。")
        with t3:
            ips = st.text_area("优选 IP（每行一条，可用 #名称）",
                               value="\n".join(cfg["preferred_ips"] or []), height=150)
            preferred_domain = st.text_input("自定义优选域名", value=cfg["preferred_domain"])
        submitted = st.form_submit_button("💾 保存配置")
    if submitted:
        new = dict(protocol=proto, uuid_str=user_id.strip(), trojan_password=trojan_pw,
                   ws_path=normalize_path(ws_path), port_vm_ws=int(port),
                   custom_domain=domain.strip(), argo_token=token.strip(),
                   outbound_mode=mode, hop1=hop1.strip(), hop2=hop2.strip(),
                   preferred_ips=[s.strip() for s in ips.splitlines() if s.strip()],
                   preferred_domain=preferred_domain.strip())
        try:
            validate(new)
            save_config(new)
            st.success("配置已保存。服务尚未重启，请按“启动/重启服务”使其生效。")
        except Exception as exc:
            st.error(str(exc))

    c1, c2, c3 = st.columns(3)
    if c1.button("🚀 启动/重启服务", use_container_width=True):
        try:
            with st.spinner("检查依赖并启动服务中..."):
                domain, links = start_services(effective_config(secrets_cfg))
            st.success(f"已启动，隧道域名：{domain}；生成 {len(links)} 条节点。")
        except Exception as exc:
            st.error("启动失败：" + str(exc))
    if c2.button("⏹ 停止服务", use_container_width=True):
        stop_services()
        st.info("已停止由此面板启动的服务。")
    if c3.button("🗑 卸载运行时文件", use_container_width=True):
        stop_services()
        if ROOT.exists():
            shutil.rmtree(ROOT)
        st.warning("运行时文件已清理；重新部署前请先备份配置。")

    if NODES.exists():
        st.subheader("节点链接")
        st.code(NODES.read_text(encoding="utf-8"))
    with st.expander("🔍 出口 IP 检测"):
        st.caption("检测按当前已保存的代理配置建立连接；它不直接检测客户端 sing-box 的实际流量。")
        if st.button("检测当前出口"):
            info, err = query_exit_ip(effective_config(secrets_cfg))
            if err:
                st.error(err)
            else:
                st.metric("出口 IP", info["ip"])
                st.write("国家/地区：", info["country"], "；链路：", info["via"])
    with st.expander("🔌 出站链路连通性测试"):
        if st.button("测试各跳 TCP 连通性"):
            for field in ("hop1", "hop2"):
                if cfg.get(field):
                    try:
                        proxy = parse_proxy_url(cfg[field])
                        ms = latency(proxy["server"], proxy["server_port"])
                        st.write(field, f"TCP {ms}ms" if ms is not None else "TCP 不可达")
                    except ValueError as exc:
                        st.error(str(exc))
            st.caption("仅检查容器直连各代理端口；完整链路请使用出口 IP 检测。")
    with st.expander("🌏 地区优选源"):
        selected = st.multiselect("选择地区", list(REGIONS), format_func=lambda x: REGIONS[x])
        limit = st.number_input("每个地区取多少条", 1, 100, 10)
        if st.button("拉取并加入优选"):
            entries = []
            for code in selected:
                try:
                    entries.extend((host, port, REGIONS[code] + f"-{i:02d}")
                                   for i, (host, port) in enumerate(fetch_region_pool(code, int(limit)), 1))
                except Exception as exc:
                    st.error(f"{REGIONS[code]} 拉取失败：{exc}")
            count = append_preferred(entries, effective_config(secrets_cfg))
            st.success(f"已加入 {count} 条，刷新页面后可查看；启动/重启后生成新节点。")
    with st.expander("📡 在线优选测速"):
        text = st.text_area("待测地址，每行一条", value="\n".join(cfg["preferred_ips"] or []))
        if st.button("开始测速"):
            jobs = [p for line in text.splitlines() if (p := parse_target_line(line))]
            results = []
            if jobs:
                with ThreadPoolExecutor(max_workers=min(16, len(jobs))) as pool:
                    futures = {pool.submit(latency, h, p): (h, p, n) for h, p, n in jobs}
                    for future in as_completed(futures):
                        ms = future.result()
                        if ms is not None:
                            results.append((*futures[future], ms))
            results.sort(key=lambda item: item[3])
            st.session_state["latency_results"] = results
        results = st.session_state.get("latency_results", [])
        if results:
            st.dataframe([{"地址": format_target(h, p), "名称": n, "延迟(ms)": ms}
                          for h, p, n, ms in results], hide_index=True)
            n = st.number_input("加入前 N 条", 1, len(results), min(10, len(results)))
            if st.button("加入优选"):
                count = append_preferred([(h, p, name or f"测速{ms}ms")
                                          for h, p, name, ms in results[:int(n)]], effective_config(secrets_cfg))
                st.success(f"已加入 {count} 条；刷新后显示在配置中。")
    st.subheader("配置备份")
    st.download_button("⬇️ 导出配置 JSON", json.dumps(cfg, ensure_ascii=False, indent=2),
                       file_name="agsb-config.json", mime="application/json")
    upload = st.file_uploader("⬆️ 导入配置 JSON", type="json")
    if upload and st.button("确认导入配置"):
        try:
            data = json.loads(upload.getvalue())
            if not isinstance(data, dict):
                raise ValueError("JSON 必须是对象")
            restored = {**DEFAULT, **{k: v for k, v in data.items() if k in DEFAULT}}
            validate(restored)
            save_config(restored)
            st.success("配置已导入。刷新页面并手动启动服务。")
        except Exception as exc:
            st.error("导入失败：" + str(exc))
    with st.expander("诊断日志（仅管理员可见）"):
        for path in (SB_LOG, CF_LOG):
            if path.exists():
                st.write(path.name)
                st.code(path.read_text(encoding="utf-8", errors="ignore")[-5000:])


def main():
    st.set_page_config(page_title="服务管理", layout="wide")
    try:
        secret = str(st.secrets.get("SECRET_KEY", ""))
        secrets_cfg = {"uuid_str": st.secrets.get("UUID_STR", ""),
                       "port_vm_ws": st.secrets.get("PORT_VM_WS", 0),
                       "custom_domain": st.secrets.get("CUSTOM_DOMAIN", ""),
                       "argo_token": st.secrets.get("ARGO_TOKEN", "")}
    except (OSError, FileNotFoundError):
        secret, secrets_cfg = "", {}
    if not secret or secret == "your_secret_password_here":
        st.error("请在 Streamlit Secrets 中配置非默认的 SECRET_KEY。")
        return
    st.session_state.setdefault("authenticated", False)
    if not st.session_state["authenticated"]:
        st.title("🔐 服务管理登录")
        password = st.text_input("管理口令", type="password")
        if st.button("登录"):
            if hmac.compare_digest(password, secret):
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("口令不正确")
        return
    if st.sidebar.button("退出登录"):
        st.session_state["authenticated"] = False
        st.rerun()
    render_panel(secrets_cfg)


if __name__ == "__main__":
    main()
