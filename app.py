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

DEFAULT = {
    "protocol": "vless",
    "uuid": "",
    "password": "",
    "ws_path": "/",
    "port": 0,
    "test_port": 0,
    "domain": "",
    "tunnel_token": "",
    "vpn_user": "vpn",
    "vpn_pass": "vpn",
}

IGNORE = {
    "client",
    "tls-client",
    "dev",
    "nobind",
    "persist-key",
    "persist-tun",
    "resolv-retry",
    "verb",
    "auth-nocache",
    "pull",
    "remote-cert-tls",
    "auth-user-pass",
    "float",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "server-poll-timeout",
}

FIELDS = {
    "remote",
    "proto",
    "cipher",
    "data-ciphers",
    "data-ciphers-fallback",
    "auth",
    "key-direction",
    "tls-version-min",
    "reneg-sec",
    "tun-mtu",
}

BLOCKS = {
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
}


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
        return {
            **DEFAULT,
            **{k: v for k, v in data.items() if k in DEFAULT},
        }
    except (OSError, ValueError, AttributeError):
        return DEFAULT.copy()


def parse_ovpn(text):
    if len(text.encode("utf-8")) > 150000:
        raise ValueError("配置文件过大")

    options = {}
    blocks = {}
    active = None
    content = []

    for raw in text.replace("\r\n", "\n").splitlines():
        line = raw.strip()

        if active:
            if line == f"</{active}>":
                blocks[active] = "\n".join(content).strip() + "\n"
                active = None
                content = []
            else:
                content.append(raw)
            continue

        if not line or line.startswith(("#", ";")):
            continue

        if line.startswith("<"):
            name = line[1:-1].lower() if line.endswith(">") else ""
            if name not in BLOCKS or name in blocks:
                raise ValueError("不支持的证书块：" + line[:60])
            active = name
            content = []
            continue

        args = shlex.split(line, comments=True)
        if not args:
            continue

        key = args[0].lower()

        if key not in IGNORE | FIELDS:
            raise ValueError("不支持的 .ovpn 指令：" + key)

        if key == "dev" and args[1:] != ["tun"\]:
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

    proto = (
        remote[2]
        if len(remote) == 3
        else (options.get("proto") or ["udp"])[0]
    ).lower()

    network = {
        "tcp-client": "tcp",
        "tcp": "tcp",
        "udp": "udp",
    }.get(proto)

    if not network:
        raise ValueError("仅支持 OpenVPN TCP 或 UDP")

    tls = {
        "certificate": [blocks["ca"]],
        "remote_certificate_tls": "server",
    }

    if blocks.get("cert"):
        tls.update(
            client_certificate=[blocks["cert"]],
            client_key=[blocks["key"]],
        )

    wraps = [
        k
        for k in ("tls-auth", "tls-crypt", "tls-crypt-v2")
        if blocks.get(k)
    ]

    if len(wraps) > 1:
        raise ValueError(
            "tls-auth、tls-crypt、tls-crypt-v2 不能同时存在"
        )

    if options.get("key-direction") and wraps != ["tls-auth"\]:
        raise ValueError("key-direction 仅适用于 tls-auth")

    if wraps:
        tls["control_wrap"] = {
            "type": wraps[0].replace("-", "_"),
            "key": [blocks[wraps[0]]],
        }

        if options.get("key-direction"):
            direction = options["key-direction"][0]
            if direction not in ("0", "1"):
                raise ValueError("key-direction 必须是 0 或 1")

            tls["control_wrap"]["direction"] = (
                "client" if direction == "1" else "server"
            )

    endpoint = {
        "type": "openvpn-client",
        "tag": "vpn-exit",
        "mode": "tls",
        "server": host,
        "server_port": port,
        "network": network,
        "system": False,
        "tls": tls,
    }

    for source, target in (
        ("auth", "auth"),
        ("cipher", "data_ciphers_fallback"),
        ("data-ciphers-fallback", "data_ciphers_fallback"),
    ):
        if options.get(source):
            endpoint[target] = options[source][0]

    if options.get("data-ciphers"):
        endpoint["data_ciphers"] = (
            options["data-ciphers"][0].split(":")
        )

    if options.get("tun-mtu"):
        endpoint["mtu"] = int(options["tun-mtu"][0])

    if options.get("reneg-sec"):
        endpoint["renegotiate_interval"] = (
            options["reneg-sec"][0] + "s"
        )

    if (
        options.get("tls-version-min")
        and options["tls-version-min"][0] != "1.2"
    ):
        raise ValueError("目前只支持 tls-version-min 1.2")

    return endpoint


def make_config(cfg, endpoint):
    if cfg["protocol"] == "trojan":
        user = {"password": cfg["password"] or cfg["uuid"]}
    else:
        user = {"uuid": cfg["uuid"]}

    if cfg["protocol"] == "vmess":
        user["alterId"] = 0

    inbound = {
        "type": cfg["protocol"],
        "tag": "client",
        "listen": "127.0.0.1",
        "listen_port": cfg["port"],
        "users": [user],
        "transport": {
            "type": "ws",
            "path": "/" + cfg["ws_path"].lstrip("/"),
        },
    }

    test = {
        "type": "socks",
        "tag": "test",
        "listen": "127.0.0.1",
        "listen_port": cfg["test_port"],
    }

    return {
        "log": {"level": "info"},
        "inbounds": [inbound, test],
        "endpoints": [endpoint],
        "route": {"final": "vpn-exit"},
    }


def get_pid(path):
    try:
        number = int(path.read_text().strip())
        return number if number > 0 else None
    except (OSError, TypeError, ValueError, OverflowError):
        return None


def ours(number, binary):
    if not number:
        return False

    try:
        proc = Path("/proc") / str(number)
        executable_matches = (
            (proc / "exe").resolve(strict=True)
            == binary.resolve(strict=True)
        )
        is_zombie = bool(
            re.search(
                r"^State:\s+Z",
                (proc / "status").read_text(),
                re.M,
            )
        )
        return executable_matches and not is_zombie
    except OSError:
        return False


def stop():
    for path, binary in (
        (CF_PID, CF_BIN),
        (SB_PID, SB_BIN),
    ):
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
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        with urllib.request.urlopen(req, timeout=35) as src:
            with tmp.open("wb") as out:
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
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())

    if platform.system() != "Linux" or not arch:
        raise RuntimeError("仅支持 Linux amd64/arm64")

    version = None

    if SB_BIN.exists():
        try:
            version = subprocess.run(
                [str(SB_BIN), "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    if (
        not version
        or version.returncode
        or not version.stdout.splitlines()
        or SB_VERSION not in version.stdout.splitlines()[0]
    ):
        folder = f"sing-box-{SB_VERSION}-linux-{arch}"
        archive = HOME / "sing-box.tar.gz"

        download(
            f"https://github.com/SagerNet/sing-box/releases/"
            f"download/v{SB_VERSION}/{folder}.tar.gz",
            archive,
        )

        with tarfile.open(archive, "r:gz") as tar:
            member = next(
                (
                    item
                    for item in tar.getmembers()
                    if item.name == folder + "/sing-box"
                    and item.isfile()
                ),
                None,
            )

            if not member:
                raise RuntimeError(
                    "sing-box 安装包内容不符合预期"
                )

            with tar.extractfile(member) as src:
                with SB_BIN.open("wb") as out:
                    shutil.copyfileobj(src, out)

        archive.unlink(missing_ok=True)
        SB_BIN.chmod(0o700)

    if not CF_BIN.exists():
        download(
            "https://github.com/cloudflare/cloudflared/"
            f"releases/latest/download/cloudflared-linux-{arch}",
            CF_BIN,
        )
        CF_BIN.chmod(0o700)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tail(path):
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )[-3500:]
    except OSError:
        return "无日志"


def quick_domain(process):
    """扫描完整日志，而不是只扫描末尾几千个字符。"""
    pattern = re.compile(
        r"https://([a-zA-Z0-9.-]+\.trycloudflare\.com)"
    )
    text = ""

    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError(
                "cloudflared 提前退出：" + tail(CF_LOG)
            )

        try:
            text = CF_LOG.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            pass

        match = pattern.search(text)
        if match:
            return match.group(1)

        time.sleep(0.5)

    raise RuntimeError(
        "完整日志里没有临时域名；日志开头："
        + text[:1800]
    )


def node_link(domain, cfg):
    path = "/" + cfg["ws_path"].lstrip("/")

    query = urlencode(
        {
            "security": "tls",
            "sni": domain,
            "type": "ws",
            "host": domain,
            "path": path,
        }
    )

    if cfg["protocol"] == "vmess":
        obj = {
            "v": "2",
            "ps": "VPN Gate",
            "add": domain,
            "port": "443",
            "id": cfg["uuid"],
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": path,
            "tls": "tls",
            "sni": domain,
        }

        return (
            "vmess://"
            + base64.b64encode(
                json.dumps(obj).encode()
            ).decode().rstrip("=")
        )

    if cfg["protocol"] == "vless":
        credential = cfg["uuid"]
        query = "encryption=none&" + query
    else:
        credential = cfg["password"] or cfg["uuid"]

    return (
        f"{cfg['protocol']}://"
        f"{quote(credential, safe='')}@{domain}:443"
        f"?{query}#VPN-Gate"
    )


def start(cfg):
    if not PROFILE.exists():
        raise ValueError(
            "先上传并保存 VPN Gate .ovpn 文件"
        )

    endpoint = parse_ovpn(
        PROFILE.read_text(encoding="utf-8")
    )
    cfg = dict(cfg)

    if cfg["protocol"] not in (
        "vless",
        "vmess",
        "trojan",
    ):
        raise ValueError("入站协议无效")

    cfg["uuid"] = cfg["uuid"] or str(uuid.uuid4())
    uuid.UUID(cfg["uuid"])

    cfg["port"] = int(
        cfg["port"] or free_port()
    )
    cfg["test_port"] = int(
        cfg["test_port"] or free_port()
    )

    if cfg["port"] == cfg["test_port"\]:
        raise ValueError(
            "检测端口与入站端口冲突"
        )

    if cfg["tunnel_token"] and not cfg["domain"\]:
        raise ValueError(
            "固定 Tunnel Token 必须填写对应的域名"
        )

    endpoint["username"] = (
        cfg["vpn_user"] or "vpn"
    )
    endpoint["password"] = (
        cfg["vpn_pass"] or "vpn"
    )

    binaries()

    write_private(
        SB_CONF,
        json.dumps(
            make_config(cfg, endpoint),
            ensure_ascii=False,
            indent=2,
        ),
    )

    check = subprocess.run(
        [str(SB_BIN), "check", "-c", str(SB_CONF)],
        capture_output=True,
        text=True,
        timeout=25,
    )

    if check.returncode:
        raise RuntimeError(
            "sing-box 配置检查失败："
            + (check.stderr or check.stdout)[-1500:]
        )

    stop()

    try:
        with SB_LOG.open("w") as out:
            sb = subprocess.Popen(
                [
                    str(SB_BIN),
                 
