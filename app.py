#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Streamlit VPN Gate panel. Secrets are authoritative; tunnel falls back to quick mode only if both values are blank."""
import base64
import csv
import hmac
import http.client
import io
import ipaddress
import json
import os
import platform
import re
import shlex
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
from urllib.parse import quote, urlencode, urlparse

import streamlit as st

HOME = Path.home() / ".agsb"
PROFILE = HOME / "vpngate.ovpn"
SB_CONF = HOME / "sb.json"
SB_BIN, CF_BIN = HOME / "sing-box", HOME / "cloudflared"
SB_PID, CF_PID = HOME / "sb.pid", HOME / "cf.pid"
SB_LOG, CF_LOG = HOME / "sb.log", HOME / "cf.log"
NODES, RUNTIME = HOME / "nodes.txt", HOME / "runtime.json"
SB_VERSION = "1.14.2"
API_URL = "https://www.vpngate.net/api/iphone/"
IGNORE = {"client", "tls-client", "nobind", "persist-key", "persist-tun", "resolv-retry", "verb", "auth-nocache", "pull", "float", "connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout"}
FIELDS = {"remote", "proto", "cipher", "data-ciphers", "data-ciphers-fallback", "auth", "key-direction", "tls-version-min", "reneg-sec", "tun-mtu"}
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}


def secret(name, default=""):
    try:
        value = st.secrets.get(name, default)
    except (OSError, FileNotFoundError):
        value = default
    return value


def write_private(path, data):
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    HOME.chmod(0o700)
    tmp = HOME / (".tmp-" + uuid.uuid4().hex)
    try:
        tmp.write_text(data, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def read_runtime():
    try:
        obj = json.loads(RUNTIME.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def choose_port(value, old=0):
    if value is None or str(value).strip() in ("", "0"):
        if isinstance(old, int) and 1 <= old <= 65535:
            return old
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("PORT_VM_WS / TEST_PORT 必须是有效端口") from exc
    if not 1 <= port <= 65535:
        raise ValueError("PORT_VM_WS / TEST_PORT 必须在 1-65535 之间")
    return port


def settings():
    """Secrets always win; generated UUID and ports are only used when blank."""
    saved = read_runtime()
    token = str(secret("ARGO_TOKEN", "") or "").strip()
    domain = str(secret("CUSTOM_DOMAIN", "") or "").strip()
    if bool(token) != bool(domain):
        raise ValueError("ARGO_TOKEN 和 CUSTOM_DOMAIN 必须同时填写，或同时留空以使用临时隧道")
    if domain:
        parsed = urlparse("https://" + domain)
        if (not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain)
                or parsed.hostname != domain.lower() or domain.startswith(".")):
            raise ValueError("CUSTOM_DOMAIN 只填写域名，不要填写 https://、路径或端口")
    uid = str(secret("UUID_STR", "") or "").strip() or str(saved.get("uuid", "") or "")
    if not uid:
        uid = str(uuid.uuid4())
    try:
        uuid.UUID(uid)
    except ValueError as exc:
        raise ValueError("UUID_STR 不是有效的 UUID") from exc
    port = choose_port(secret("PORT_VM_WS", ""), saved.get("port", 0))
    test_port = choose_port(secret("TEST_PORT", ""), saved.get("test_port", 0))
    if port == test_port:
        raise ValueError("TEST_PORT 不能与 PORT_VM_WS 相同")
    protocol = str(secret("PROTOCOL", "vless") or "vless").lower().strip()
    if protocol not in ("vless", "vmess", "trojan"):
        raise ValueError("PROTOCOL 只能是 vless、vmess 或 trojan")
    cfg = {"protocol": protocol, "uuid": uid, "port": port, "test_port": test_port,
           "ws_path": "/" + str(secret("WS_PATH", "/") or "/").strip().lstrip("/"),
           "trojan_password": str(secret("TROJAN_PASSWORD", "") or ""),
           "vpn_user": str(secret("VPN_USER", "vpn") or "vpn"),
           "vpn_pass": str(secret("VPN_PASS", "vpn") or "vpn"),
           "token": token, "domain": domain}
    # Only generated non-secret values are persisted. Secrets are never copied into runtime.json.
    write_private(RUNTIME, json.dumps({"uuid": uid, "port": port, "test_port": test_port}))
    return cfg


def parse_ovpn(text):
    if len(text.encode("utf-8")) > 150000:
        raise ValueError(".ovpn 文件超过 150 KB")
    opts, blocks, active, buf, user_pass = {}, {}, None, [], False
    for raw in text.replace("\r\n", "\n").splitlines():
        line = raw.strip()
        if active:
            if line == f"</{active}>":
                blocks[active] = "\n".join(buf).strip() + "\n"
                active, buf = None, []
            else:
                buf.append(raw)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<"):
            tag = line[1:-1].lower() if line.endswith(">") else ""
            if tag not in BLOCKS or tag in blocks:
                raise ValueError("不支持或重复的内联块：" + line[:60])
            active, buf = tag, []
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ValueError(".ovpn 指令格式错误") from exc
        if not parts:
            continue
        key, args = parts[0].lower(), parts[1:]
        if key == "auth-user-pass":
            if args:
                raise ValueError("不支持外部凭据文件")
            user_pass = True
        elif key == "dev":
            if args != ["tun"]:
                raise ValueError("仅支持 dev tun")
        elif key == "remote-cert-tls":
            if args != ["server"]:
                raise ValueError("仅支持 remote-cert-tls server")
        elif key == "setenv":
            if len(args) < 2 or args[0] not in ("CLIENT_CERT", "UV_DEVICE_ID"):
                raise ValueError("不支持的 setenv 参数")
        elif key in FIELDS:
            if key == "remote" and key in opts:
                raise ValueError("仅支持单个 remote")
            opts[key] = args
        elif key not in IGNORE:
            raise ValueError("不支持的 .ovpn 指令：" + key)
    if active or not blocks.get("ca"):
        raise ValueError("缺少完整内联 <ca> 证书")
    if bool(blocks.get("cert")) != bool(blocks.get("key")):
        raise ValueError("<cert> 和 <key> 必须同时提供")
    remote = opts.get("remote", [])
    if len(remote) not in (2, 3):
        raise ValueError("remote 必须包含主机和端口")
    host = remote[0]
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host):
        raise ValueError("remote 主机格式无效")
    try:
        port = int(remote[1])
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError as exc:
        raise ValueError("remote 端口无效") from exc
    proto = (remote[2] if len(remote) == 3 else (opts.get("proto") or ["udp"])[0]).lower()
    network = {"tcp-client": "tcp", "tcp": "tcp", "udp": "udp"}.get(proto)
    if not network:
        raise ValueError("仅支持 OpenVPN TCP/UDP")
    tls = {"certificate": [blocks["ca"]], "remote_certificate_tls": "server"}
    if blocks.get("cert"):
        tls.update(client_certificate=[blocks["cert"]], client_key=[blocks["key"]])
    wraps = [k for k in ("tls-auth", "tls-crypt", "tls-crypt-v2") if blocks.get(k)]
    if len(wraps) > 1 or (opts.get("key-direction") and wraps != ["tls-auth"]):
        raise ValueError("tls-auth/tls-crypt/key-direction 配置冲突")
    if wraps:
        tls["control_wrap"] = {"type": wraps[0].replace("-", "_"), "key": [blocks[wraps[0]]]}
        if opts.get("key-direction"):
            direction = opts["key-direction"][0]
            if direction not in ("0", "1"):
                raise ValueError("key-direction 必须为 0 或 1")
            tls["control_wrap"]["direction"] = "client" if direction == "1" else "server"
    endpoint = {"type": "openvpn-client", "tag": "vpn-exit", "mode": "tls",
                "server": host, "server_port": port, "network": network, "system": False, "tls": tls}
    for src, dest in (("auth", "auth"), ("cipher", "data_ciphers_fallback"),
                      ("data-ciphers-fallback", "data_ciphers_fallback")):
        if opts.get(src):
            endpoint[dest] = opts[src][0]
    if opts.get("data-ciphers"):
        endpoint["data_ciphers"] = opts["data-ciphers"][0].split(":")
    if opts.get("tun-mtu"):
        endpoint["mtu"] = int(opts["tun-mtu"][0])
    if opts.get("reneg-sec"):
        endpoint["renegotiate_interval"] = opts["reneg-sec"][0] + "s"
    if opts.get("tls-version-min") and opts["tls-version-min"][0] != "1.2":
        raise ValueError("仅支持 tls-version-min 1.2")
    return endpoint, user_pass


def global_ipv4(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address) and addr.is_global
    except ValueError:
        return False


def candidates(country, limit):
    req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        final = urlparse(resp.geturl())
        if final.scheme != "https" or final.hostname not in ("www.vpngate.net", "api.vpngate.net") or final.path != "/api/iphone/":
            raise ValueError("节点源不在 VPN Gate 官方 API 地址")
        raw = resp.read(80_000_001)
    if len(raw) > 80_000_000:
        raise ValueError("CSV 超过 80 MB")
    content = raw.decode("utf-8-sig", errors="replace")
    pos = content.find("#HostName,IP,Score,Ping,Speed,")
    if pos < 0:
        raise ValueError("VPN Gate 未返回预期 CSV")
    rows = csv.DictReader(io.StringIO(content[pos + 1:]))
    if not {"IP", "CountryShort", "Speed", "OpenVPN_ConfigData_Base64"}.issubset(rows.fieldnames or []):
        raise ValueError("CSV 字段不完整")
    result, seen = [], set()
    for row in rows:
        if len(result) >= limit:
            break
        if country != "全部" and (row.get("CountryShort") or "").upper() != country:
            continue
        ip = (row.get("IP") or "").strip()
        if not global_ipv4(ip):
            continue
        b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if row.get(None):
            b64 = row[None][-1].strip()
        if not 100 <= len(b64) <= 200000:
            continue
        try:
            profile = base64.b64decode(b64, validate=True).decode("utf-8-sig")
            ep, _ = parse_ovpn(profile)
            if ep["network"] != "tcp":
                continue
            hostname = (row.get("HostName") or "").strip().lower().rstrip(".")
            remote = ep["server"].lower().rstrip(".")
            if remote != ip and remote not in (hostname, hostname + ".opengw.net"):
                continue
            identity = (ip, ep["server_port"])
            if identity in seen:
                continue
            seen.add(identity)
            result.append({"host": hostname or ip, "ip": ip, "port": ep["server_port"],
                           "country": row.get("CountryShort", ""),
                           "speed": round(max(0, int(row.get("Speed") or 0)) / 1e6, 1),
                           "ping": row.get("Ping", "?"), "profile": profile, "latency": None})
        except (ValueError, UnicodeError, TypeError, IndexError, OverflowError):
            continue
    if not result:
        raise ValueError("没有找到兼容的 TCP OpenVPN 候选；可换地区或手动上传 .ovpn")
    return result


def probe(item):
    start = time.monotonic()
    try:
        with socket.create_connection((item["ip"], item["port"]), timeout=1.6):
            return round((time.monotonic() - start) * 1000, 1)
    except OSError:
        return None


def benchmark(items):
    with ThreadPoolExecutor(max_workers=8) as pool:
        future_map = {pool.submit(probe, item): item for item in items}
        for f in as_completed(future_map):
            future_map[f]["latency"] = f.result()
    items.sort(key=lambda x: (x["latency"] is None, x["latency"] or 1e9, -x["speed"]))
    return items


def make_config(cfg, endpoint):
    user = ({"password": cfg["trojan_password"] or cfg["uuid"]} if cfg["protocol"] == "trojan"
            else {"uuid": cfg["uuid"]})
    if cfg["protocol"] == "vmess":
        user["alterId"] = 0
    return {"log": {"level": "info"},
            "inbounds": [{"type": cfg["protocol"], "tag": "client", "listen": "127.0.0.1",
                          "listen_port": cfg["port"], "users": [user],
                          "transport": {"type": "ws", "path": cfg["ws_path"]}},
                         {"type": "socks", "tag": "test", "listen": "127.0.0.1",
                          "listen_port": cfg["test_port"]}],
            "endpoints": [endpoint], "route": {"final": "vpn-exit"}}


def pid(path):
    try:
        n = int(path.read_text().strip())
        return n if n > 0 else None
    except (OSError, TypeError, ValueError, OverflowError):
        return None


def ours(n, binary):
    if not n:
        return False
    try:
        proc = Path("/proc") / str(n)
        return ((proc / "exe").resolve(strict=True) == binary.resolve(strict=True)
                and not re.search(r"^State:\s+Z", (proc / "status").read_text(), re.M))
    except OSError:
        return False


def stop():
    for path, binary in ((CF_PID, CF_BIN), (SB_PID, SB_BIN)):
        n = pid(path)
        if ours(n, binary):
            try:
                os.kill(n, 15)
            except OSError:
                pass
        path.unlink(missing_ok=True)
    NODES.unlink(missing_ok=True)


def log_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def download(url, target):
    HOME.mkdir(parents=True, exist_ok=True)
    tmp = HOME / (".download-" + uuid.uuid4().hex)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=35) as src, tmp.open("wb") as dst:
            size = 0
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > 100_000_000:
                    raise RuntimeError("下载超过 100 MB")
                dst.write(chunk)
        tmp.replace(target)
    finally:
        tmp.unlink(missing_ok=True)


def binaries():
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if platform.system() != "Linux" or not arch:
        raise RuntimeError("仅支持 Linux amd64/arm64")
    version = None
    if SB_BIN.exists():
        try:
            version = subprocess.run([str(SB_BIN), "version"], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not version or version.returncode or not version.stdout.splitlines() or SB_VERSION not in version.stdout.splitlines()[0]:
        folder = f"sing-box-{SB_VERSION}-linux-{arch}"
        archive = HOME / "sing-box.tar.gz"
        download(f"https://github.com/SagerNet/sing-box/releases/download/v{SB_VERSION}/{folder}.tar.gz", archive)
        with tarfile.open(archive, "r:gz") as tar:
            member = next((x for x in tar.getmembers() if x.name == folder + "/sing-box" and x.isfile()), None)
            if member is None:
                raise RuntimeError("sing-box 安装包内容异常")
            with tar.extractfile(member) as src, SB_BIN.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        archive.unlink(missing_ok=True)
        SB_BIN.chmod(0o700)
    if not CF_BIN.exists():
        download(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}", CF_BIN)
        CF_BIN.chmod(0o700)


def quick_domain(proc):
    pattern = re.compile(r"https://([a-zA-Z0-9.-]+\.trycloudflare\.com)")
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError("cloudflared 提前退出：" + log_text(CF_LOG)[-1500:])
        match = pattern.search(log_text(CF_LOG))
        if match:
            return match.group(1)
        time.sleep(.5)
    raise RuntimeError("完整 cloudflared 日志未发现临时域名：" + log_text(CF_LOG)[:1500])


def node_link(domain, cfg):
    q = urlencode({"security": "tls", "sni": domain, "type": "ws", "host": domain, "path": cfg["ws_path"]})
    if cfg["protocol"] == "vmess":
        obj = {"v": "2", "ps": "VPN Gate", "add": domain, "port": "443", "id": cfg["uuid"],
               "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": domain,
               "path": cfg["ws_path"], "tls": "tls", "sni": domain}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    credential = cfg["uuid"] if cfg["protocol"] == "vless" else cfg["trojan_password"] or cfg["uuid"]
    if cfg["protocol"] == "vless":
        q = "encryption=none&" + q
    return f"{cfg['protocol']}://{quote(credential, safe='')}@{domain}:443?{q}#VPN-Gate"


def start(cfg):
    if not PROFILE.exists():
        raise ValueError("先添加候选节点或手动上传 .ovpn")
    endpoint, needs_password = parse_ovpn(PROFILE.read_text(encoding="utf-8"))
    if needs_password:
        endpoint["username"] = cfg["vpn_user"]
        endpoint["password"] = cfg["vpn_pass"]
    binaries()
    write_private(SB_CONF, json.dumps(make_config(cfg, endpoint), ensure_ascii=False, indent=2))
    check = subprocess.run([str(SB_BIN), "check", "-c", str(SB_CONF)], capture_output=True, text=True, timeout=25)
    if check.returncode:
        raise RuntimeError("sing-box 配置检查失败：" + (check.stderr or check.stdout)[-1500:])
    stop()
    try:
        with SB_LOG.open("w") as out:
            sb = subprocess.Popen([str(SB_BIN), "run", "-c", str(SB_CONF)], cwd=HOME,
                                  stdout=out, stderr=subprocess.STDOUT)
        write_private(SB_PID, str(sb.pid))
        for _ in range(30):
            if sb.poll() is not None:
                raise RuntimeError("sing-box 提前退出：" + log_text(SB_LOG)[-1500:])
            try:
                with socket.create_connection(("127.0.0.1", cfg["port"]), timeout=.3):
                    break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError("sing-box 本地入口未就绪：" + log_text(SB_LOG)[-1500:])
        if cfg["token"]:
            cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "run", "--token", cfg["token"]]
        else:
            cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "--url",
                   f"http://127.0.0.1:{cfg['port']}", "--protocol", "http2"]
        with CF_LOG.open("w") as out:
            cf = subprocess.Popen(cmd, cwd=HOME, stdout=out, stderr=subprocess.STDOUT)
        write_private(CF_PID, str(cf.pid))
        domain = cfg["domain"] if cfg["token"] else quick_domain(cf)
        if cf.poll() is not None:
            raise RuntimeError("cloudflared 已退出：" + log_text(CF_LOG)[-1500:])
        if "authentication failed" in log_text(SB_LOG).lower():
            raise RuntimeError("VPN 认证失败；检查 .ovpn 或更换节点")
        write_private(NODES, node_link(domain, cfg) + "\n")
        return domain
    except Exception:
        stop()
        raise


def recv_exact(sock, n):
    result = b""
    while len(result) < n:
        block = sock.recv(n - len(result))
        if not block:
            raise OSError("连接提前断开")
        result += block
    return result


def verify_exit(port):
    host = "api.country.is"
    sock = socket.create_connection(("127.0.0.1", port), timeout=15)
    sock.settimeout(15)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS 协商失败")
        name = host.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        reply = recv_exact(sock, 4)
        if reply[1] != 0:
            raise OSError("OpenVPN 出站尚未就绪，SOCKS 错误码 " + str(reply[1]))
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = recv_exact(sock, 1)[0]
        if size is None:
            raise OSError("SOCKS 地址类型无效")
        recv_exact(sock, size + 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n".encode())
            resp = http.client.HTTPResponse(tls)
            resp.begin()
            if resp.status != 200:
                raise OSError("出口查询 HTTP " + str(resp.status))
            data = json.loads(resp.read(20000))
            if not data.get("ip"):
                raise OSError("出口查询未返回 IP")
            return data
    finally:
        sock.close()


def main():
    st.set_page_config(page_title="VPN Gate 节点优选", layout="wide")
    password = str(secret("SECRET_KEY", "") or "")
    if not password or password == "your_secret_password_here":
        st.error("请在 Streamlit App settings -> Secrets 设置非默认 SECRET_KEY")
        return
    if not st.session_state.get("authenticated"):
        st.title("管理登录")
        attempt = st.text_input("管理口令", type="password")
        if st.button("登录"):
            if hmac.compare_digest(attempt, password):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("口令错误")
        return
    if st.sidebar.button("退出登录"):
        st.session_state.authenticated = False
        st.session_state.pop("candidates", None)
        st.rerun()
    st.title("VPN Gate OpenVPN 出站")
    try:
        cfg = settings()
    except Exception as exc:
        st.error("Secrets 配置错误：" + str(exc))
        return
    mode = "固定域名" if cfg["token"] else "临时隧道（Secrets 中 Token 和域名均为空）"
    st.caption(f"配置来自 Streamlit Secrets；当前入口模式：{mode}；仅手动启动服务。")
    st.write("sing-box：", "运行中" if ours(pid(SB_PID), SB_BIN) else "未运行",
             "；cloudflared：", "运行中" if ours(pid(CF_PID), CF_BIN) else "未运行")
    st.subheader("VPN Gate 候选优选")
    st.caption("仅自动筛选 TCP OpenVPN；本机测速仅是 TCP 建连延迟，官网 Speed 不等于本地下载速度。")
    col1, col2 = st.columns(2)
    country = col1.selectbox("国家/地区", ["JP", "KR", "US", "全部"])
    limit = col2.slider("候选上限", 5, 40, 20, step=5)
    if st.button("拉取并测试候选"):
        try:
            with st.spinner("读取清单并测试 TCP 可达性..."):
                found = benchmark(candidates(country, limit))
            st.session_state.candidates = found
            st.success(f"已测试 {len(found)} 个候选；选择并添加后仍需由你启动")
        except Exception as exc:
            st.session_state.pop("candidates", None)
            st.error("拉取或测试失败：" + str(exc))
    found = st.session_state.get("candidates", [])
    if found:
        st.dataframe([{"序号": i + 1, "节点": c["host"], "国家": c["country"],
                       "本机TCP延迟(ms)": c["latency"] if c["latency"] is not None else "不可达",
                       "官网Speed(Mbps)": c["speed"], "官网Ping(ms)": c["ping"],
                       "IP": c["ip"], "端口": c["port"]} for i, c in enumerate(found)],
                     use_container_width=True, hide_index=True)
        available = [i for i, c in enumerate(found) if c["latency"] is not None]
        if available:
            selected = st.selectbox("选择候选", available,
                                    format_func=lambda i: f"{i + 1}. {found[i]['host']} / {found[i]['latency']} ms")
            if st.button("添加所选节点（不启动）"):
                write_private(PROFILE, found[selected]["profile"])
                st.success("已保存 .ovpn；当前运行连接未切换。请由你点击启动/重启服务。")
    upload = st.file_uploader("或手动上传 VPN Gate .ovpn", type=["ovpn"])
    if upload is not None and st.button("保存上传的 .ovpn（不启动）"):
        try:
            text = upload.getvalue().decode("utf-8-sig")
            parse_ovpn(text)
            write_private(PROFILE, text)
            st.success("已保存 .ovpn；不会自动启动")
        except Exception as exc:
            st.error(".ovpn 不兼容：" + str(exc))
    if PROFILE.exists():
        try:
            ep, auth = parse_ovpn(PROFILE.read_text(encoding="utf-8"))
            st.info(f"已保存落地：{ep['server']}:{ep['server_port']} / {ep['network']}；账号认证：{'需要' if auth else '配置未要求'}")
        except Exception as exc:
            st.warning("已保存 .ovpn 无效：" + str(exc))
    a, b, c = st.columns(3)
    if a.button("启动/重启服务", use_container_width=True):
        try:
            with st.spinner("检查配置并启动..."):
                domain = start(cfg)
            st.success("隧道域名：" + domain)
            st.info("服务启动不等于 VPN 出口成功，请点击验证实际出口")
        except Exception as exc:
            st.error("启动失败：" + str(exc))
    if b.button("验证实际出口", use_container_width=True):
        try:
            if not ours(pid(SB_PID), SB_BIN):
                raise RuntimeError("sing-box 未运行")
            data = verify_exit(cfg["test_port"])
            st.success(f"sing-box 出口 IP：{data['ip']}；地区代码：{data.get('country', '')}")
        except Exception as exc:
            st.error("验证失败：" + str(exc))
    if c.button("停止服务", use_container_width=True):
        stop()
        st.info("已停止本项目记录的进程")
    if NODES.exists():
        st.subheader("节点链接")
        st.code(NODES.read_text(encoding="utf-8"))
    with st.expander("诊断日志"):
        for path in (SB_LOG, CF_LOG):
            st.write(path.name)
            st.code(log_text(path)[-3500:] or "无日志")


if __name__ == "__main__":
    main()
