#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Streamlit-only VPN Gate OpenVPN egress experiment.
Requires Streamlit Secrets SECRET_KEY. Import a VPN Gate .ovpn profile,
then click Start. No VPN or binary is started on anonymous page visits.
"""
import base64
import hmac
import http.client
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
from pathlib import Path
from urllib.parse import quote, urlencode

import streamlit as st

ROOT = Path.home() / ".agsb"
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
PROFILE = ROOT / "vpngate.ovpn"
CONFIG = ROOT / "config.json"
SB_JSON = ROOT / "sb.json"
SB_BIN = ROOT / "sing-box"
CF_BIN = ROOT / "cloudflared"
SB_PID = ROOT / "sbpid.log"
CF_PID = ROOT / "sbargopid.log"
SB_LOG = ROOT / "sb.log"
CF_LOG = ROOT / "argo.log"
NODES = ROOT / "allnodes.txt"
VERSION = "1.14.2"
DEFAULT = {"protocol": "vless", "uuid_str": "", "trojan_password": "",
           "ws_path": "/", "port_vm_ws": 0, "test_port": 0,
           "argo_token": "", "custom_domain": "", "preferred_ips": [],
           "vpn_user": "vpn", "vpn_password": "vpn"}
# Explicitly supported directives; reject unknown directives rather than silently
# ignoring potentially important OpenVPN authentication/security options.
NOOP = {"client", "tls-client", "dev", "nobind", "persist-key", "persist-tun",
        "resolv-retry", "verb", "auth-nocache", "pull", "remote-random",
        "remote-cert-tls", "auth-user-pass", "setenv", "float", "connect-retry",
        "connect-retry-max", "connect-timeout", "server-poll-timeout"}
SUPPORTED = NOOP | {"remote", "proto", "cipher", "data-ciphers",
                    "data-ciphers-fallback", "auth", "key-direction",
                    "tls-version-min", "reneg-sec", "tun-mtu"}
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}


def atomic_write(path, text):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    temp = ROOT / (".tmp-" + uuid.uuid4().hex)
    try:
        with temp.open("x", encoding="utf-8") as f:
            f.write(text)
        temp.chmod(0o600)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def read_config():
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**DEFAULT, **{k: v for k, v in data.items() if k in DEFAULT}}
    except (OSError, ValueError):
        pass
    return DEFAULT.copy()


def save_config(cfg):
    atomic_write(CONFIG, json.dumps(cfg, ensure_ascii=False, indent=2))


def normalize_path(path):
    return "/" + str(path or "/").strip().lstrip("/")


def parse_profile(text):
    if len(text.encode("utf-8")) > 150000:
        raise ValueError(".ovpn 文件超过 150 KB")
    lines = text.replace("\r\n", "\n").splitlines()
    directives, blocks, active, buf = {}, {}, None, []
    for raw in lines:
        line = raw.strip()
        if active:
            if line == "</" + active + ">":
                blocks[active] = "\n".join(buf).strip() + "\n"
                active, buf = None, []
            else:
                buf.append(raw)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<"):
            name = line[1:-1].lower() if line.endswith(">") else ""
            if name not in BLOCKS or name in blocks:
                raise ValueError("不支持或重复的内联块：" + line[:60])
            active, buf = name, []
            continue
        try:
            args = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ValueError(".ovpn 指令解析失败") from exc
        if not args:
            continue
        key = args[0].lower()
        if key not in SUPPORTED:
            raise ValueError("不支持的 .ovpn 指令：" + key + "；请换一份兼容配置")
        if key == "dev" and args[1:] != ["tun"]:
            raise ValueError("仅支持 dev tun")
        if key == "remote-cert-tls" and args[1:] != ["server"]:
            raise ValueError("仅支持 remote-cert-tls server")
        if key == "auth-user-pass" and len(args) > 1:
            raise ValueError("不支持外部凭据文件；请在面板填写用户名和密码")
        if key == "setenv" and (len(args) < 2 or args[1] not in ("CLIENT_CERT", "UV_DEVICE_ID")):
            raise ValueError("不支持 setenv 参数：" + " ".join(args[1:])[:60])
        if key in ("remote", "proto"):
            directives.setdefault(key, []).append(args[1:])
        elif key not in NOOP:
            directives[key] = args[1:]
    if active:
        raise ValueError(".ovpn 内联块未闭合：" + active)
    if not blocks.get("ca"):
        raise ValueError("需要内联 <ca> 证书；不读取外部文件")
    if bool(blocks.get("cert")) != bool(blocks.get("key")):
        raise ValueError("<cert> 和 <key> 必须同时提供")
    proto = (directives.get("proto") or [["udp"]])[-1]
    network = proto[0].lower() if proto else "udp"
    network = {"tcp-client": "tcp", "tcp": "tcp", "udp": "udp"}.get(network)
    if not network:
        raise ValueError("仅支持 TCP/UDP OpenVPN")
    remotes = directives.get("remote", [])
    if len(remotes) != 1 or len(remotes[0]) not in (2, 3):
        raise ValueError("此实验版仅支持一条 remote 主机 端口")
    host, port_str = remotes[0][:2]
    if len(remotes[0]) == 3:
        network = {"tcp-client": "tcp", "tcp": "tcp", "udp": "udp"}.get(remotes[0][2].lower())
        if not network:
            raise ValueError("remote 协议仅支持 TCP/UDP")
    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError as exc:
        raise ValueError("OpenVPN remote 端口无效") from exc
    if not re.fullmatch(r"[a-zA-Z0-9.:-]{1,253}", host):
        raise ValueError("OpenVPN remote 地址格式错误")
    if sum(bool(blocks.get(k)) for k in ("tls-auth", "tls-crypt", "tls-crypt-v2")) > 1:
        raise ValueError("tls-auth 与 tls-crypt 不能同时使用")
    if directives.get("key-direction") and not blocks.get("tls-auth"):
        raise ValueError("key-direction 仅适用于 tls-auth")
    tls = {"certificate": [blocks["ca"]], "remote_certificate_tls": "server"}
    if blocks.get("cert"):
        tls["client_certificate"] = [blocks["cert"]]
        tls["client_key"] = [blocks["key"]]
    for key, kind in (("tls-auth", "tls_auth"), ("tls-crypt", "tls_crypt"),
                      ("tls-crypt-v2", "tls_crypt_v2")):
        if blocks.get(key):
            tls["control_wrap"] = {"type": kind, "key": [blocks[key]]}
            if key == "tls-auth" and directives.get("key-direction"):
                direction = directives["key-direction"][0]
                if direction not in ("0", "1"):
                    raise ValueError("key-direction 必须为 0 或 1")
                tls["control_wrap"]["direction"] = "client" if direction == "1" else "server"
    endpoint = {"type": "openvpn-client", "tag": "vpn-exit", "mode": "tls",
                "server": host, "server_port": port, "network": network,
                "system": False, "tls": tls}
    if directives.get("auth"):
        endpoint["auth"] = directives["auth"][0]
    if directives.get("cipher"):
        endpoint["data_ciphers_fallback"] = directives["cipher"][0]
    if directives.get("data-ciphers"):
        endpoint["data_ciphers"] = directives["data-ciphers"][0].split(":")
    if directives.get("data-ciphers-fallback"):
        endpoint["data_ciphers_fallback"] = directives["data-ciphers-fallback"][0]
    if directives.get("tun-mtu"):
        endpoint["mtu"] = int(directives["tun-mtu"][0])
    if directives.get("reneg-sec"):
        endpoint["renegotiate_interval"] = directives["reneg-sec"][0] + "s"
    if directives.get("tls-version-min") and directives["tls-version-min"][0] != "1.2":
        raise ValueError("当前仅支持 tls-version-min 1.2")
    return endpoint


def build_config(cfg, endpoint):
    user = {"password": cfg.get("trojan_password") or cfg["uuid_str"]} if cfg["protocol"] == "trojan" else {"uuid": cfg["uuid_str"]}
    if cfg["protocol"] == "vmess":
        user["alterId"] = 0
    return {"log": {"level": "info"},
            "inbounds": [
                {"type": cfg["protocol"], "tag": "client-in", "listen": "127.0.0.1",
                 "listen_port": cfg["port_vm_ws"], "users": [user],
                 "transport": {"type": "ws", "path": normalize_path(cfg["ws_path"])}},
                {"type": "socks", "tag": "local-test", "listen": "127.0.0.1",
                 "listen_port": cfg["test_port"]}],
            "endpoints": [endpoint], "outbounds": [],
            "route": {"final": "vpn-exit"}}


def pid(path):
    try:
        result = int(path.read_text().strip())
        return result if result > 0 else None
    except (OSError, TypeError, ValueError, OverflowError):
        return None


def is_ours(number, binary):
    if not isinstance(number, int) or number <= 0:
        return False
    try:
        exe = (Path("/proc") / str(number) / "exe").resolve(strict=True)
        state = (Path("/proc") / str(number) / "status").read_text()
        return exe == binary.resolve(strict=True) and not re.search(r"^State:\s+Z", state, re.M)
    except OSError:
        return False


def stop():
    for path, binary in ((CF_PID, CF_BIN), (SB_PID, SB_BIN)):
        number = pid(path)
        if is_ours(number, binary):
            try:
                os.kill(number, 15)
            except OSError:
                pass
        path.unlink(missing_ok=True)


def status():
    return is_ours(pid(SB_PID), SB_BIN), is_ours(pid(CF_PID), CF_BIN)


def download(url, target, max_bytes=100_000_000):
    temp = ROOT / (".download-" + uuid.uuid4().hex)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=35) as src, temp.open("wb") as out:
            size = 0
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise RuntimeError("下载文件超过大小限制")
                out.write(chunk)
        temp.replace(target)
    finally:
        temp.unlink(missing_ok=True)


def ensure_binaries():
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if platform.system() != "Linux" or not arch:
        raise RuntimeError("仅支持 Linux amd64/arm64")
    version = subprocess.run([str(SB_BIN), "version"], capture_output=True, text=True, timeout=10) if SB_BIN.exists() else None
    if not version or version.returncode or not version.stdout.splitlines() or VERSION not in version.stdout.splitlines()[0]:
        folder = f"sing-box-{VERSION}-linux-{arch}"
        archive = ROOT / "sing-box.tar.gz"
        download(f"https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{folder}.tar.gz", archive)
        with tarfile.open(archive, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.name == folder + "/sing-box" and m.isfile()), None)
            if member is None:
                raise RuntimeError("sing-box 压缩包中没有预期的程序")
            with tar.extractfile(member) as src, SB_BIN.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        archive.unlink(missing_ok=True)
        SB_BIN.chmod(0o700)
    if not CF_BIN.exists():
        cf_arch = "amd64" if arch == "amd64" else "arm64"
        download(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}", CF_BIN)
        CF_BIN.chmod(0o700)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def log_tail(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-3500:]
    except OSError:
        return "无日志"


def wait_port(port, process):
    for _ in range(30):
        if process.poll() is not None:
            raise RuntimeError("sing-box 提前退出：" + log_tail(SB_LOG))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.3):
                return
        except OSError:
            time.sleep(.2)
    raise RuntimeError("sing-box 监听端口未就绪：" + log_tail(SB_LOG))


def quick_domain(process):
    for _ in range(30):
        if process.poll() is not None:
            raise RuntimeError("cloudflared 提前退出：" + log_tail(CF_LOG))
        m = re.search(r"https://([a-zA-Z0-9.-]+\.trycloudflare\.com)", log_tail(CF_LOG))
        if m:
            return m[1]
        time.sleep(.5)
    raise RuntimeError("临时隧道没有返回域名：" + log_tail(CF_LOG))


def links(domain, cfg):
    targets = []
    for line in cfg.get("preferred_ips") or []:
        raw, _, name = line.partition("#")
        raw = raw.strip()
        m = re.fullmatch(r"(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::(\d{1,5}))?", raw)
        if m:
            host = m[1].strip("[]")
            port = int(m[2] or 443)
            if 0 < port < 65536:
                targets.append((host, port, name.strip() or "优选"))
    targets.append((domain, 443, "隧道直连"))
    result = []
    for host, port, name in targets:
        q = urlencode({"security": "tls", "sni": domain, "type": "ws", "host": domain,
                       "path": normalize_path(cfg["ws_path"])})
        authority = ("[" + host + "]" if ":" in host else host) + f":{port}"
        if cfg["protocol"] == "vmess":
            obj = {"v": "2", "ps": name, "add": host, "port": str(port), "id": cfg["uuid_str"],
                   "aid": "0", "scy": "auto", "net": "ws", "type": "none",
                   "host": domain, "path": normalize_path(cfg["ws_path"]), "tls": "tls", "sni": domain}
            result.append("vmess://" + base64.b64encode(json.dumps(obj).encode()).decode().rstrip("="))
        else:
            credential = cfg["uuid_str"] if cfg["protocol"] == "vless" else cfg.get("trojan_password") or cfg["uuid_str"]
            if cfg["protocol"] == "vless":
                q = "encryption=none&" + q
            result.append(f"{cfg['protocol']}://{quote(credential, safe='')}@{authority}?{q}#{quote(name)}")
    return result


def start(cfg):
    if not PROFILE.exists():
        raise ValueError("请先上传 VPN Gate 的 .ovpn 文件")
    endpoint = parse_profile(PROFILE.read_text(encoding="utf-8"))
    cfg = dict(cfg)
    if cfg["protocol"] not in ("vmess", "vless", "trojan"):
        raise ValueError("协议不支持")
    if not cfg.get("uuid_str"):
        cfg["uuid_str"] = str(uuid.uuid4())
    uuid.UUID(cfg["uuid_str"])
    cfg["port_vm_ws"] = int(cfg.get("port_vm_ws") or free_port())
    cfg["test_port"] = int(cfg.get("test_port") or free_port())
    if cfg["port_vm_ws"] == cfg["test_port"]:
        raise ValueError("本地入口端口与检测端口不能相同")
    endpoint["username"] = cfg.get("vpn_user") or "vpn"
    endpoint["password"] = cfg.get("vpn_password") or "vpn"
    ensure_binaries()
    atomic_write(SB_JSON, json.dumps(build_config(cfg, endpoint), ensure_ascii=False, indent=2))
    checked = subprocess.run([str(SB_BIN), "check", "-c", str(SB_JSON)],
                             capture_output=True, text=True, timeout=25)
    if checked.returncode:
        raise RuntimeError("sing-box 配置检查失败：" + (checked.stderr or checked.stdout)[-1200:])
    stop()
    try:
        with SB_LOG.open("w") as out:
            sb = subprocess.Popen([str(SB_BIN), "run", "-c", str(SB_JSON)], cwd=ROOT,
                                  stdout=out, stderr=subprocess.STDOUT)
        atomic_write(SB_PID, str(sb.pid))
        wait_port(cfg["port_vm_ws"], sb)
        if cfg.get("argo_token"):
            if not cfg.get("custom_domain"):
                raise ValueError("固定隧道 Token 需要自定义域名")
            cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "run", "--token", cfg["argo_token"]]
        else:
            cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "--url",
                   f"http://127.0.0.1:{cfg['port_vm_ws']}", "--protocol", "http2"]
        with CF_LOG.open("w") as out:
            cf = subprocess.Popen(cmd, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
        atomic_write(CF_PID, str(cf.pid))
        domain = cfg["custom_domain"] if cfg.get("argo_token") else quick_domain(cf)
        if cf.poll() is not None:
            raise RuntimeError("cloudflared 已退出：" + log_tail(CF_LOG))
        node_links = links(domain, cfg)
        atomic_write(NODES, "\n".join(node_links) + "\n")
        save_config(cfg)
        return domain
    except Exception:
        stop()
        raise


def recv_exact(sock, n):
    result = b""
    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk:
            raise OSError("连接提前断开")
        result += chunk
    return result


def verify_exit(port):
    """Request IP through the actual sing-box SOCKS inbound, not a parallel test chain."""
    host = "api.country.is"
    sock = socket.create_connection(("127.0.0.1", int(port)), timeout=12)
    sock.settimeout(12)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("本地 SOCKS 握手失败")
        dest = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(dest)]) + dest + (443).to_bytes(2, "big"))
        response = recv_exact(sock, 4)
        if len(response) != 4 or response[1] != 0:
            raise OSError("OpenVPN 出站未连通（SOCKS CONNECT 失败）")
        atyp = response[3]
        if atyp == 1:
            length = 4
        elif atyp == 4:
            length = 16
        elif atyp == 3:
            length = recv_exact(sock, 1)[0]
        else:
            raise OSError("SOCKS 响应地址无效")
        remaining = length + 2
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise OSError("SOCKS 响应不完整")
            remaining -= len(chunk)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n".encode())
            reply = http.client.HTTPResponse(tls)
            reply.begin()
            if reply.status != 200:
                raise OSError("出口查询 HTTP " + str(reply.status))
            data = json.loads(reply.read(20000))
            if not data.get("ip"):
                raise OSError("查询接口未返回 IP")
            return data
    finally:
        sock.close()


def main():
    st.set_page_config(page_title="VPN Gate 出站管理", layout="wide")
    try:
        secret = str(st.secrets.get("SECRET_KEY", ""))
    except (OSError, FileNotFoundError):
        secret = ""
    if not secret or secret == "your_secret_password_here":
        st.error("请先在 Streamlit Secrets 配置非默认 SECRET_KEY")
        return
    if not st.session_state.get("authenticated"):
        st.title("🔐 VPN Gate 出站管理")
        password = st.text_input("管理口令", type="password")
        if st.button("登录"):
            if hmac.compare_digest(password, secret):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("口令错误")
        return
    if st.sidebar.button("退出登录"):
        st.session_state.authenticated = False
        st.rerun()
    cfg = read_config()
    st.title("VPN Gate OpenVPN 出站")
    st.caption("仅 Streamlit Cloud 容器内运行 sing-box 与 cloudflared；不需要 Cloudflare Worker。")
    a, b = status()
    st.write("sing-box：", "运行中" if a else "未运行", "；cloudflared：", "运行中" if b else "未运行")
    upload = st.file_uploader("上传 VPN Gate 的 OpenVPN .ovpn 配置", type=["ovpn"])
    if upload is not None and st.button("保存 .ovpn"):
        try:
            content = upload.getvalue().decode("utf-8-sig")
            parsed = parse_profile(content)
            atomic_write(PROFILE, content)
            st.success(f"已保存：{parsed['server']}:{parsed['server_port']} / {parsed['network']}")
        except Exception as exc:
            st.error("配置不兼容：" + str(exc))
    if PROFILE.exists():
        try:
            ep = parse_profile(PROFILE.read_text(encoding="utf-8"))
            st.info(f"当前 VPN：{ep['server']}:{ep['server_port']} / {ep['network']}")
        except Exception as exc:
            st.warning("已保存的配置无效：" + str(exc))
    with st.form("settings"):
        proto = st.selectbox("入站协议", ["vless", "vmess", "trojan"],
                             index=["vless", "vmess", "trojan"].index(cfg["protocol"]) if cfg["protocol"] in ("vless", "vmess", "trojan") else 0)
        user_id = st.text_input("UUID（留空首次启动生成）", cfg["uuid_str"])
        trojan_pw = st.text_input("Trojan 密码", cfg["trojan_password"], type="password")
        path = st.text_input("WebSocket 路径", cfg["ws_path"])
        vpn_user = st.text_input("VPN Gate 用户名", cfg["vpn_user"])
        vpn_pass = st.text_input("VPN Gate 密码", cfg["vpn_password"], type="password")
        custom_domain = st.text_input("固定隧道域名（使用 Token 时必填）", cfg["custom_domain"])
        token = st.text_input("Cloudflare Tunnel Token（留空使用临时隧道）", cfg["argo_token"], type="password")
        ips = st.text_area("优选地址（可选，每行一个 IP:端口#名称）", "\n".join(cfg["preferred_ips"] or []))
        saved = st.form_submit_button("保存配置")
    if saved:
        try:
            if user_id.strip():
                uuid.UUID(user_id.strip())
            cfg.update(protocol=proto, uuid_str=user_id.strip(), trojan_password=trojan_pw,
                       ws_path=normalize_path(path), vpn_user=vpn_user.strip(), vpn_password=vpn_pass,
                       custom_domain=custom_domain.strip(), argo_token=token.strip(),
                       preferred_ips=[x.strip() for x in ips.splitlines() if x.strip()])
            save_config(cfg)
            st.success("配置已保存；请点击启动/重启服务")
        except Exception as exc:
            st.error(str(exc))
    col1, col2, col3 = st.columns(3)
    if col1.button("启动/重启服务", use_container_width=True):
        try:
            with st.spinner("下载依赖、检查配置并启动服务..."):
                domain = start(read_config())
            st.success("服务进程已启动，隧道域名：" + domain)
            st.info("尚未证明 VPN 握手成功；请点击“验证实际出口”。")
        except Exception as exc:
            st.error("启动失败：" + str(exc))
    if col2.button("验证实际出口", use_container_width=True):
        try:
            if not status()[0]:
                raise RuntimeError("sing-box 未运行")
            data = verify_exit(read_config()["test_port"])
            st.success("sing-box 实际出口 IP：" + str(data["ip"]) + "；地区代码：" + str(data.get("country", "")))
        except Exception as exc:
            st.error("VPN 出口验证失败，不应当视为已成功连接：" + str(exc))
    if col3.button("停止服务", use_container_width=True):
        stop()
        st.info("已停止本应用记录的服务进程")
    if NODES.exists():
        st.subheader("节点链接")
        st.code(NODES.read_text(encoding="utf-8"))
    with st.expander("配置备份与诊断日志"):
        if PROFILE.exists():
            st.download_button("导出当前 .ovpn（可能含私钥，请妥善保管）",
                               PROFILE.read_bytes(), file_name="vpngate.ovpn",
                               mime="application/octet-stream")
        st.download_button("导出配置 JSON（包含凭据，请妥善保管）", json.dumps(cfg, ensure_ascii=False, indent=2),
                           file_name="agsb-config.json", mime="application/json")
        for log in (SB_LOG, CF_LOG):
            st.write(log.name)
            st.code(log_tail(log))


if __name__ == "__main__":
    main()
