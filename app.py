#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Streamlit 面板：sing-box OpenVPN 出站 + cloudflared 入站（实验版）。"""
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
SB_PID, CF_PID = HOME / "sb.pid", HOME / "cf.pid"
SB_LOG, CF_LOG = HOME / "sb.log", HOME / "cf.log"
NODES = HOME / "nodes.txt"
SB_VERSION = "1.14.2"
DEFAULT = dict(protocol="vless", uuid="", password="", ws_path="/",
               port=0, test_port=0, domain="", tunnel_token="",
               vpn_user="vpn", vpn_pass="vpn")
IGNORE = {"client", "tls-client", "nobind", "persist-key", "persist-tun",
          "resolv-retry", "verb", "auth-nocache", "pull", "float",
          "connect-retry", "connect-retry-max", "connect-timeout",
          "server-poll-timeout"}
FIELDS = {"remote", "proto", "cipher", "data-ciphers", "data-ciphers-fallback",
          "auth", "key-direction", "tls-version-min", "reneg-sec", "tun-mtu"}
BLOCKS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}


def write_private(path, text):
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    HOME.chmod(0o700)
    tmp = HOME / (".tmp-" + uuid.uuid4().hex)
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def settings():
    try:
        obj = json.loads(SETTINGS.read_text(encoding="utf-8"))
        if isinstance(obj, dict):
            return {**DEFAULT, **{k: v for k, v in obj.items() if k in DEFAULT}}
    except (OSError, ValueError):
        pass
    return DEFAULT.copy()


def parse_ovpn(text):
    """只接收已实现的指令；不能静默忽略可能影响认证的参数。"""
    if len(text.encode("utf-8")) > 150000:
        raise ValueError(".ovpn 文件超过 150 KB")
    opts, blocks, active, buf = {}, {}, None, []
    auth_user_pass = False
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
            args = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ValueError(".ovpn 指令解析失败") from exc
        if not args:
            continue
        key, values = args[0].lower(), args[1:]
        if key == "auth-user-pass":
            if values:
                raise ValueError("不支持外部凭据文件，请在面板填写 VPN 账号")
            auth_user_pass = True
        elif key == "dev":
            if values != ["tun"]:
                raise ValueError("仅支持 dev tun")
        elif key == "remote-cert-tls":
            if values != ["server"]:
                raise ValueError("仅支持 remote-cert-tls server")
        elif key == "setenv":
            if len(values) < 2 or values[0] not in ("CLIENT_CERT", "UV_DEVICE_ID"):
                raise ValueError("不支持的 setenv 参数：" + " ".join(values)[:60])
        elif key in FIELDS:
            if key == "remote" and key in opts:
                raise ValueError("当前仅支持一个 remote")
            opts[key] = values
        elif key not in IGNORE:
            raise ValueError("不支持的 .ovpn 指令：" + key)
    if active:
        raise ValueError("内联块未闭合：" + active)
    if not blocks.get("ca"):
        raise ValueError("需要内联 <ca> 证书")
    if bool(blocks.get("cert")) != bool(blocks.get("key")):
        raise ValueError("<cert> 和 <key> 必须同时存在")
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
    if len(wraps) > 1:
        raise ValueError("tls-auth 与 tls-crypt 系列不可同时使用")
    if opts.get("key-direction") and wraps != ["tls-auth"]:
        raise ValueError("key-direction 仅适用于 tls-auth")
    if wraps:
        tls["control_wrap"] = {"type": wraps[0].replace("-", "_"), "key": [blocks[wraps[0]]]}
        if opts.get("key-direction"):
            direction = opts["key-direction"][0]
            if direction not in ("0", "1"):
                raise ValueError("key-direction 必须为 0 或 1")
            tls["control_wrap"]["direction"] = "client" if direction == "1" else "server"
    ep = {"type": "openvpn-client", "tag": "vpn-exit", "mode": "tls",
          "server": host, "server_port": port, "network": network,
          "system": False, "tls": tls}
    for src, dest in (("auth", "auth"), ("cipher", "data_ciphers_fallback"),
                      ("data-ciphers-fallback", "data_ciphers_fallback")):
        if opts.get(src):
            ep[dest] = opts[src][0]
    if opts.get("data-ciphers"):
        ep["data_ciphers"] = opts["data-ciphers"][0].split(":")
    if opts.get("tun-mtu"):
        ep["mtu"] = int(opts["tun-mtu"][0])
    if opts.get("reneg-sec"):
        ep["renegotiate_interval"] = opts["reneg-sec"][0] + "s"
    if opts.get("tls-version-min") and opts["tls-version-min"][0] != "1.2":
        raise ValueError("仅支持 tls-version-min 1.2")
    return ep, auth_user_pass


def make_config(cfg, endpoint):
    user = ({"password": cfg["password"] or cfg["uuid"]} if cfg["protocol"] == "trojan"
            else {"uuid": cfg["uuid"]})
    if cfg["protocol"] == "vmess":
        user["alterId"] = 0
    return {"log": {"level": "info"},
            "inbounds": [
                {"type": cfg["protocol"], "tag": "client", "listen": "127.0.0.1",
                 "listen_port": cfg["port"], "users": [user],
                 "transport": {"type": "ws", "path": "/" + cfg["ws_path"].lstrip("/")}},
                {"type": "socks", "tag": "test", "listen": "127.0.0.1",
                 "listen_port": cfg["test_port"]}],
            "endpoints": [endpoint], "route": {"final": "vpn-exit"}}


def get_pid(path):
    try:
        n = int(path.read_text().strip())
        return n if n > 0 else None
    except (OSError, ValueError, TypeError, OverflowError):
        return None


def ours(number, binary):
    if not number:
        return False
    try:
        proc = Path("/proc") / str(number)
        return ((proc / "exe").resolve(strict=True) == binary.resolve(strict=True)
                and not re.search(r"^State:\s+Z", (proc / "status").read_text(), re.M))
    except OSError:
        return False


def stop():
    for path, binary in ((CF_PID, CF_BIN), (SB_PID, SB_BIN)):
        n = get_pid(path)
        if ours(n, binary):
            try:
                os.kill(n, 15)
            except OSError:
                pass
        path.unlink(missing_ok=True)


def download(url, path):
    HOME.mkdir(parents=True, exist_ok=True)
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
                    raise RuntimeError("下载超过 100 MB")
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
                raise RuntimeError("sing-box 压缩包不含预期程序")
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


def log_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def quick_domain(process):
    pattern = re.compile(r"https://([a-zA-Z0-9.-]+\.trycloudflare\.com)")
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError("cloudflared 提前退出：" + log_text(CF_LOG)[-1500:])
        text = log_text(CF_LOG)  # 扫描完整日志，域名可能位于开头
        match = pattern.search(text)
        if match:
            return match.group(1)
        time.sleep(.5)
    raise RuntimeError("完整 cloudflared 日志未找到域名；日志开头：" + log_text(CF_LOG)[:1500])


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
        raise ValueError("请先上传并保存 VPN Gate 的 .ovpn 文件")
    endpoint, needs_password = parse_ovpn(PROFILE.read_text(encoding="utf-8"))
    cfg = dict(cfg)
    if cfg["protocol"] not in ("vless", "vmess", "trojan"):
        raise ValueError("入站协议无效")
    cfg["uuid"] = cfg["uuid"] or str(uuid.uuid4())
    uuid.UUID(cfg["uuid"])
    cfg["port"] = int(cfg["port"] or free_port())
    cfg["test_port"] = int(cfg["test_port"] or free_port())
    if cfg["port"] == cfg["test_port"]:
        raise ValueError("入口端口与检测端口冲突")
    if cfg["tunnel_token"] and not cfg["domain"]:
        raise ValueError("固定 Tunnel Token 需要对应域名")
    if needs_password:  # 修复：证书认证的 .ovpn 不强行注入用户名/密码
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
                raise RuntimeError("sing-box 提前退出：" + log_text(SB_LOG)[-1500:])
            try:
                with socket.create_connection(("127.0.0.1", cfg["port"]), timeout=.3):
                    break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError("sing-box 入口未就绪：" + log_text(SB_LOG)[-1500:])
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
            raise RuntimeError("cloudflared 已退出：" + log_text(CF_LOG)[-1500:])
        if "authentication failed" in log_text(SB_LOG).lower():
            raise RuntimeError("VPN 认证失败；请检查 .ovpn 是否需要 auth-user-pass、证书是否匹配，以及节点是否可用")
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
    """通过 sing-box 本地 SOCKS 入口查询 IP，不使用 Python 直连。"""
    host = "api.country.is"
    sock = socket.create_connection(("127.0.0.1", int(port)), timeout=15)
    sock.settimeout(15)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("本地 SOCKS 协商失败")
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
    st.write("sing-box：", "运行中" if ours(get_pid(SB_PID), SB_BIN) else "未运行",
             "；cloudflared：", "运行中" if ours(get_pid(CF_PID), CF_BIN) else "未运行")
    upload = st.file_uploader("VPN Gate .ovpn 配置", type=["ovpn"])
    if upload is not None and st.button("保存 .ovpn"):
        try:
            text = upload.getvalue().decode("utf-8-sig")
            endpoint, auth = parse_ovpn(text)
            write_private(PROFILE, text)
            st.success(f"已保存 {endpoint['server']}:{endpoint['server_port']} / {endpoint['network']}；账号认证：{'需要' if auth else '配置未要求'}")
        except Exception as exc:
            st.error(".ovpn 不兼容：" + str(exc))
    if PROFILE.exists():
        try:
            ep, auth = parse_ovpn(PROFILE.read_text(encoding="utf-8"))
            st.info(f"当前 VPN：{ep['server']}:{ep['server_port']} / {ep['network']}；账号认证：{'需要' if auth else '配置未要求'}")
        except Exception as exc:
            st.warning("当前 .ovpn 无效：" + str(exc))
    with st.form("settings_form"):
        choices = ["vless", "vmess", "trojan"]
        protocol = st.selectbox("入站协议", choices, index=choices.index(cfg["protocol"]) if cfg["protocol"] in choices else 0)
        uid = st.text_input("UUID（留空自动生成）", cfg["uuid"])
        pw = st.text_input("Trojan 密码", cfg["password"], type="password")
        path = st.text_input("WebSocket 路径", cfg["ws_path"])
        vpn_user = st.text_input("VPN 用户名", cfg["vpn_user"])
        vpn_pass = st.text_input("VPN 密码", cfg["vpn_pass"], type="password")
        domain = st.text_input("固定 Tunnel 域名（Token 模式必填）", cfg["domain"])
        token = st.text_input("Tunnel Token（留空使用临时隧道）", cfg["tunnel_token"], type="password")
        submitted = st.form_submit_button("保存配置")
    if submitted:
        try:
            if uid.strip():
                uuid.UUID(uid.strip())
            cfg.update(protocol=protocol, uuid=uid.strip(), password=pw,
                       ws_path="/" + path.strip().lstrip("/"), vpn_user=vpn_user.strip(),
                       vpn_pass=vpn_pass, domain=domain.strip(), tunnel_token=token.strip())
            write_private(SETTINGS, json.dumps(cfg, ensure_ascii=False, indent=2))
            st.success("配置已保存；点击启动/重启服务后生效")
        except Exception as exc:
            st.error("保存失败：" + str(exc))
    c1, c2, c3 = st.columns(3)
    if c1.button("启动/重启服务", use_container_width=True):
        try:
            with st.spinner("检查配置并启动..."):
                name = start(settings())
            st.success("隧道域名：" + name)
            st.info("进程启动不代表 VPN 握手成功，请点击验证实际出口")
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
            if "authentication failed" in log_text(SB_LOG).lower():
                st.error("sing-box 日志显示 VPN 认证失败；更换匹配的 .ovpn 或核对认证要求")
    if c3.button("停止服务", use_container_width=True):
        stop()
        st.info("已停止本项目记录的进程")
    if NODES.exists():
        st.subheader("节点链接")
        st.code(NODES.read_text(encoding="utf-8"))
    with st.expander("诊断日志和备份"):
        if PROFILE.exists():
            st.download_button("导出 .ovpn（可能含私钥）", PROFILE.read_bytes(), file_name="vpngate.ovpn")
        st.download_button("导出配置 JSON（含凭据）", json.dumps(settings(), ensure_ascii=False, indent=2),
                           file_name="agsb-settings.json", mime="application/json")
        for path in (SB_LOG, CF_LOG):
            st.write(path.name)
            st.code(log_text(path)[-3500:] or "无日志")


if __name__ == "__main__":
    main()
