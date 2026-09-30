#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Streamlit + sing-box OpenVPN 出站；需要 Secrets 中的 SECRET_KEY。"""
import base64
import hmac
import http.client
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

HOME = Path.home() / ".agsb"
PROFILE = HOME / "vpngate.ovpn"
SETTINGS = HOME / "settings.json"
SB_CONF = HOME / "sb.json"
SB_BIN = HOME / "sing-box"
CF_BIN = HOME / "cloudflared"
SB_PID = HOME / "sb.pid"
CF_PID = HOME / "cf.pid"
SB_LOG = HOME / "sb.log"
CF_LOG = HOME / "cf.log"
NODES = HOME / "nodes.txt"
SB_VERSION = "1.14.2"
DEFAULT = {"protocol": "vless", "uuid": "", "password": "",
           "ws_path": "/", "port": 0, "test_port": 0,
           "domain": "", "tunnel_token": "", "vpn_user": "vpn", "vpn_pass": "vpn"}
IGNORE = {"client", "tls-client", "dev", "nobind", "persist-key", "persist-tun",
          "resolv-retry", "verb", "auth-nocache", "pull", "remote-cert-tls",
          "auth-user-pass", "float", "connect-retry", "connect-retry-max",
          "connect-timeout", "server-poll-timeout"}
FIELDS = {"remote", "proto", "cipher", "data-ciphers", "data-ciphers-fallback",
          "auth", "key-direction", "tls-version-min", "reneg-sec", "tun-mtu"}
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}


def write_private(path, data):
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(HOME, 0o700)
    tmp = HOME / (".tmp-" + uuid.uuid4().hex)
    try:
        with tmp.open("x", encoding="utf-8") as out:
            out.write(data)
        tmp.chmod(0o600)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def settings():
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
        return {**DEFAULT, **{k: v for k, v in data.items() if k in DEFAULT}}
    except (OSError, ValueError, AttributeError):
        return DEFAULT.copy()


def parse_ovpn(text):
    if len(text.encode("utf-8")) > 150000:
        raise ValueError("配置文件过大")
    options, blocks, active, content = {}, {}, None, []
    for raw in text.replace("\r\n", "\n").splitlines():
        line = raw.strip()
        if active:
            if line == f"</{active}>":
                blocks[active] = "\n".join(content).strip() + "\n"
                active, content = None, []
            else:
                content.append(raw)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<"):
            name = line[1:-1].lower() if line.endswith(">") else ""
            if name not in BLOCKS or name in blocks:
                raise ValueError("不支持的证书块：" + line[:60])
            active, content = name, []
            continue
        args = shlex.split(line, comments=True)
        if not args:
            continue
        key = args[0].lower()
        if key not in IGNORE | FIELDS:
            raise ValueError("不支持的 .ovpn 指令：" + key)
        if key == "dev" and args[1:] != ["tun"]:
            raise ValueError("仅支持 dev tun")
        if key == "auth-user-pass" and len(args) != 1:
            raise ValueError("请在面板填写 VPN 用户名和密码")
        if key == "remote-cert-tls" and args[1:] != ["server"]:
            raise ValueError("仅支持 remote-cert-tls server")
        if key in FIELDS:
            if key == "remote" and key in options:
                raise ValueError("仅支持一个 remote")
            options[key] = args[1:]
    if active:
        raise ValueError("证书块未闭合：" + active)
    if not blocks.get("ca"):
        raise ValueError(".ovpn 必须包含内联 <ca> 证书")
    if bool(blocks.get("cert")) != bool(blocks.get("key")):
        raise ValueError("<cert> 和 <key> 必须同时存在")
    remote = options.get("remote", [])
    if len(remote) not in (2, 3):
        raise ValueError("remote 必须包含主机和端口")
    host = remote[0]
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host):
        raise ValueError("remote 主机无效")
    try:
        port = int(remote[1])
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError as exc:
        raise ValueError("remote 端口无效") from exc
    proto = (remote[2] if len(remote) == 3 else (options.get("proto") or ["udp"])[0]).lower()
    network = {"tcp-client": "tcp", "tcp": "tcp", "udp": "udp"}.get(proto)
    if not network:
        raise ValueError("仅支持 OpenVPN TCP 或 UDP")
    tls = {"certificate": [blocks["ca"]], "remote_certificate_tls": "server"}
    if blocks.get("cert"):
        tls.update(client_certificate=[blocks["cert"]], client_key=[blocks["key"]])
    wraps = [k for k in ("tls-auth", "tls-crypt", "tls-crypt-v2") if blocks.get(k)]
    if len(wraps) > 1:
        raise ValueError("tls-auth、tls-crypt、tls-crypt-v2 不能同时存在")
    if options.get("key-direction") and wraps != ["tls-auth"]:
        raise ValueError("key-direction 仅适用于 tls-auth")
    if wraps:
        tls["control_wrap"] = {"type": wraps[0].replace("-", "_"), "key": [blocks[wraps[0]]]}
        if options.get("key-direction"):
            direction = options["key-direction"][0]
            if direction not in ("0", "1"):
                raise ValueError("key-direction 必须是 0 或 1")
            tls["control_wrap"]["direction"] = "client" if direction == "1" else "server"
    ep = {"type": "openvpn-client", "tag": "vpn-exit", "mode": "tls",
          "server": host, "server_port": port, "network": network,
          "system": False, "tls": tls}
    for source, target in (("auth", "auth"), ("cipher", "data_ciphers_fallback"),
                           ("data-ciphers-fallback", "data_ciphers_fallback")):
        if options.get(source):
            ep[target] = options[source][0]
    if options.get("data-ciphers"):
        ep["data_ciphers"] = options["data-ciphers"][0].split(":")
    if options.get("tun-mtu"):
        ep["mtu"] = int(options["tun-mtu"][0])
    if options.get("reneg-sec"):
        ep["renegotiate_interval"] = options["reneg-sec"][0] + "s"
    if options.get("tls-version-min") and options["tls-version-min"][0] != "1.2":
        raise ValueError("目前只支持 tls-version-min 1.2")
    return ep


def make_config(cfg, endpoint):
    user = ({"password": cfg["password"] or cfg["uuid"]} if cfg["protocol"] == "trojan"
            else {"uuid": cfg["uuid"]})
    if cfg["protocol"] == "vmess":
        user["alterId"] = 0
    inbound = {"type": cfg["protocol"], "tag": "client", "listen": "127.0.0.1",
               "listen_port": cfg["port"], "users": [user],
               "transport": {"type": "ws", "path": "/" + cfg["ws_path"].lstrip("/")}}
    test = {"type": "socks", "tag": "test", "listen": "127.0.0.1",
            "listen_port": cfg["test_port"]}
    return {"log": {"level": "info"}, "inbounds": [inbound, test],
            "endpoints": [endpoint], "route": {"final": "vpn-exit"}}


def get_pid(path):
    try:
        n = int(path.read_text().strip())
        return n if n > 0 else None
    except (OSError, TypeError, ValueError, OverflowError):
        return None


def ours(number, binary):
    if not number:
        return False
    try:
        proc = Path("/proc") / str(number)
        return (proc / "exe").resolve(strict=True) == binary.resolve(strict=True) and not re.search(
            r"^State:\s+Z", (proc / "status").read_text(), re.M)
    except OSError:
        return False


def stop():
    for path, binary in ((CF_PID, CF_BIN), (SB_PID, SB_BIN)):
        number = get_pid(path)
        if ours(number, binary):
            try:
                os.kill(number, 15)
            except OSError:
                pass
        path.unlink(missing_ok=True)


def download(url, path):
    tmp = HOME / (".download-" + uuid.uuid4().hex)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=35) as src, tmp.open("wb") as out:
            total = 0
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > 100_000_000:
                    raise RuntimeError("下载超出 100 MB")
                out.write(block)
        tmp.replace(path)
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
            member = next((m for m in tar.getmembers() if m.name == folder + "/sing-box" and m.isfile()), None)
            if not member:
                raise RuntimeError("sing-box 安装包内容不符合预期")
            with tar.extractfile(member) as src, SB_BIN.open("wb") as out:
                shutil.copyfileobj(src, out)
        archive.unlink(missing_ok=True)
        SB_BIN.chmod(0o700)
    if not CF_BIN.exists():
        download(f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}", CF_BIN)
        CF_BIN.chmod(0o700)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tail(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-3500:]
    except OSError:
        return "无日志"


def quick_domain(process):
    """读取完整日志：域名通常打印在预检日志之前。"""
    pattern = re.compile(r"https://([a-zA-Z0-9.-]+\.trycloudflare\.com)")
    text = ""
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError("cloudflared 提前退出：" + tail(CF_LOG))
        try:
            text = CF_LOG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        match = pattern.search(text)
        if match:
            return match.group(1)
        time.sleep(0.5)
    raise RuntimeError("完整日志里没有临时域名；日志开头：" + text[:1800])


def node_link(domain, cfg):
    path = "/" + cfg["ws_path"].lstrip("/")
    query = urlencode({"security": "tls", "sni": domain, "type": "ws", "host": domain, "path": path})
    if cfg["protocol"] == "vmess":
        obj = {"v": "2", "ps": "VPN Gate", "add": domain, "port": "443",
               "id": cfg["uuid"], "aid": "0", "scy": "auto", "net": "ws",
               "type": "none", "host": domain, "path": path, "tls": "tls", "sni": domain}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    credential = cfg["uuid"] if cfg["protocol"] == "vless" else cfg["password"] or cfg["uuid"]
    if cfg["protocol"] == "vless":
        query = "encryption=none&" + query
    return f"{cfg['protocol']}://{quote(credential, safe='')}@{domain}:443?{query}#VPN-Gate"


def start(cfg):
    if not PROFILE.exists():
        raise ValueError("先上传并保存 VPN Gate .ovpn 文件")
    endpoint = parse_ovpn(PROFILE.read_text(encoding="utf-8"))
    cfg = dict(cfg)
    if cfg["protocol"] not in ("vless", "vmess", "trojan"):
        raise ValueError("入站协议无效")
    cfg["uuid"] = cfg["uuid"] or str(uuid.uuid4())
    uuid.UUID(cfg["uuid"])
    cfg["port"] = int(cfg["port"] or free_port())
    cfg["test_port"] = int(cfg["test_port"] or free_port())
    if cfg["port"] == cfg["test_port"]:
        raise ValueError("检测端口与入站端口冲突")
    if cfg["tunnel_token"] and not cfg["domain"]:
        raise ValueError("固定 Tunnel Token 必须填写对应的域名")
    endpoint["username"] = cfg["vpn_user"] or "vpn"
    endpoint["password"] = cfg["vpn_pass"] or "vpn"
    binaries()
    write_private(SB_CONF, json.dumps(make_config(cfg, endpoint), ensure_ascii=False, indent=2))
    check = subprocess.run([str(SB_BIN), "check", "-c", str(SB_CONF)],
                           capture_output=True, text=True, timeout=25)
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
                raise RuntimeError("sing-box 已退出：" + tail(SB_LOG))
            try:
                with socket.create_connection(("127.0.0.1", cfg["port"]), timeout=.3):
                    break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError("sing-box 本地端口未就绪：" + tail(SB_LOG))
        if cfg["tunnel_token"]:
            cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "run", "--token", cfg["tunnel_token"]]
        else:
            cmd = [str(CF_BIN), "tunnel", "--no-autoupdate", "--url",
                   f"http://127.0.0.1:{cfg['port']}", "--protocol", "http2"]
        with CF_LOG.open("w") as out:
            cf = subprocess.Popen(cmd, cwd=HOME, stdout=out, stderr=subprocess.STDOUT)
        write_private(CF_PID, str(cf.pid))
        domain = cfg["domain"] if cfg["tunnel_token"] else quick_domain(cf)
        if cf.poll() is not None:
            raise RuntimeError("cloudflared 已退出：" + tail(CF_LOG))
        write_private(NODES, node_link(domain, cfg) + "\n")
        write_private(SETTINGS, json.dumps(cfg, ensure_ascii=False, indent=2))
        return domain
    except Exception:
        stop()
        raise


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("连接提前断开")
        data += chunk
    return data


def verify_exit(port):
    """走 sing-box 本地 SOCKS 入站，不用 Python 直连测 IP。"""
    host = "api.country.is"
    sock = socket.create_connection(("127.0.0.1", int(port)), timeout=15)
    sock.settimeout(15)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS 协商失败")
        name = host.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        reply = recv_exact(sock, 4)
        if reply[1] != 0:
            raise OSError("VPN 出站连接失败，SOCKS 错误码 " + str(reply[1]))
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
                raise OSError("查询服务 HTTP " + str(resp.status))
            data = json.loads(resp.read(20000))
            if not data.get("ip"):
                raise OSError("查询服务未返回 IP")
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
        st.error("请在 Streamlit Secrets 中设置非默认的 SECRET_KEY")
        return
    if not st.session_state.get("logged_in"):
        st.title("VPN Gate 出站管理登录")
        password = st.text_input("管理口令", type="password")
        if st.button("登录"):
            if hmac.compare_digest(password, secret):
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("口令错误")
        return
    if st.sidebar.button("退出登录"):
        st.session_state.logged_in = False
        st.rerun()
    cfg = settings()
    st.title("VPN Gate OpenVPN 出站")
    st.caption("本程序不会在显示页面前自动启动 VPN；先上传 .ovpn，再保存配置并启动。")
    st.write("sing-box：", "运行中" if ours(get_pid(SB_PID), SB_BIN) else "未运行",
             "；cloudflared：", "运行中" if ours(get_pid(CF_PID), CF_BIN) else "未运行")
    upload = st.file_uploader("VPN Gate .ovpn 配置", type=["ovpn"])
    if upload is not None and st.button("保存 .ovpn"):
        try:
            text = upload.getvalue().decode("utf-8-sig")
            endpoint = parse_ovpn(text)
            write_private(PROFILE, text)
            st.success(f"已保存 {endpoint['server']}:{endpoint['server_port']} / {endpoint['network']}")
        except Exception as exc:
            st.error(".ovpn 不兼容：" + str(exc))
    if PROFILE.exists():
        try:
            ep = parse_ovpn(PROFILE.read_text(encoding="utf-8"))
            st.info(f"当前 VPN：{ep['server']}:{ep['server_port']} / {ep['network']}")
        except Exception as exc:
            st.warning("当前配置无效：" + str(exc))
    with st.form("settings_form"):
        choices = ["vless", "vmess", "trojan"]
        protocol = st.selectbox("入站协议", choices, index=choices.index(cfg["protocol"]) if cfg["protocol"] in choices else 0)
        uid = st.text_input("UUID（留空自动生成）", cfg["uuid"])
        pw = st.text_input("Trojan 密码", cfg["password"], type="password")
        path = st.text_input("WebSocket 路径", cfg["ws_path"])
        vpn_user = st.text_input("VPN 用户名", cfg["vpn_user"])
        vpn_pass = st.text_input("VPN 密码", cfg["vpn_pass"], type="password")
        domain = st.text_input("固定 Tunnel 域名（使用 Token 时必填）", cfg["domain"])
        token = st.text_input("Tunnel Token（留空使用临时隧道）", cfg["tunnel_token"], type="password")
        submitted = st.form_submit_button("保存配置")
    if submitted:
        try:
            if uid.strip():
                uuid.UUID(uid.strip())
            cfg.update(protocol=protocol, uuid=uid.strip(), password=pw,
                       ws_path="/" + path.strip().lstrip("/"),
                       vpn_user=vpn_user.strip(), vpn_pass=vpn_pass,
                       domain=domain.strip(), tunnel_token=token.strip())
            write_private(SETTINGS, json.dumps(cfg, ensure_ascii=False, indent=2))
            st.success("已保存；点击启动/重启服务后才会生效")
        except Exception as exc:
            st.error("保存失败：" + str(exc))
    c1, c2, c3 = st.columns(3)
    if c1.button("启动/重启服务", use_container_width=True):
        try:
            with st.spinner("检查配置并启动..."):
                name = start(settings())
            st.success("隧道域名：" + name)
            st.info("服务进程启动不等于 VPN 已连接；请点击验证实际出口")
        except Exception as exc:
            st.error("启动失败：" + str(exc))
    if c2.button("验证实际出口", use_container_width=True):
        try:
            if not ours(get_pid(SB_PID), SB_BIN):
                raise RuntimeError("sing-box 未运行")
            data = verify_exit(settings()["test_port"])
            st.success(f"sing-box 出口 IP：{data['ip']}；地区代码：{data.get('country', '')}")
        except Exception as exc:
            st.error("验证失败：" + str(exc))
    if c3.button("停止服务", use_container_width=True):
        stop()
        st.info("已停止本项目的进程")
    if NODES.exists():
        st.subheader("节点链接")
        st.code(NODES.read_text(encoding="utf-8"))
    with st.expander("诊断日志和备份"):
        if PROFILE.exists():
            st.download_button("导出 .ovpn（可能含私钥）", PROFILE.read_bytes(),
                               file_name="vpngate.ovpn")
        st.download_button("导出配置 JSON（含凭据）", json.dumps(settings(), ensure_ascii=False, indent=2),
                           file_name="agsb-settings.json", mime="application/json")
        for log in (SB_LOG, CF_LOG):
            st.write(log.name)
            st.code(tail(log))


if __name__ == "__main__":
    main()
