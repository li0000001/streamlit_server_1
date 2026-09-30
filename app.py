#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VPN Gate Streamlit panel: probe every fetched compatible candidate via OpenVPN handshake.
The probe does not download from third-party websites and never switches the live service.
"""
from throughput_probe import render_speed_test
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
import statistics
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

import streamlit as st

HOME = Path.home() / '.agsb'
PROFILE = HOME / 'vpngate.ovpn'
RUNTIME = HOME / 'runtime.json'
SB_CONF = HOME / 'sb.json'
SB_BIN, CF_BIN = HOME / 'sing-box', HOME / 'cloudflared'
SB_PID, CF_PID = HOME / 'sb.pid', HOME / 'cf.pid'
SB_LOG, CF_LOG = HOME / 'sb.log', HOME / 'cf.log'
NODES = HOME / 'nodes.txt'
SB_VERSION = '1.14.2'
API_URL = 'https://www.vpngate.net/api/iphone/'
IGNORE = {'client', 'tls-client', 'nobind', 'persist-key', 'persist-tun',
          'resolv-retry', 'verb', 'auth-nocache', 'pull', 'float',
          'connect-retry', 'connect-retry-max', 'connect-timeout', 'server-poll-timeout'}
FIELDS = {'remote', 'proto', 'cipher', 'data-ciphers', 'data-ciphers-fallback',
          'auth', 'key-direction', 'tls-version-min', 'reneg-sec', 'tun-mtu'}
BLOCKS = {'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2'}
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def secret(name, default=''):
    try:
        return st.secrets.get(name, default)
    except (OSError, FileNotFoundError):
        return default


def write_private(path, text):
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    HOME.chmod(0o700)
    tmp = HOME / ('.tmp-' + uuid.uuid4().hex)
    try:
        tmp.write_text(text, encoding='utf-8')
        tmp.chmod(0o600)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def read_runtime():
    try:
        data = json.loads(RUNTIME.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_port(raw, previous):
    if raw is None or str(raw).strip() in ('', '0'):
        if isinstance(previous, int) and 1 <= previous <= 65535:
            return previous
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError('端口必须是整数') from exc
    if not 1 <= value <= 65535:
        raise ValueError('端口必须在 1-65535 之间')
    return value


def settings():
    saved = read_runtime()
    token = str(secret('ARGO_TOKEN', '') or '').strip()
    domain = str(secret('CUSTOM_DOMAIN', '') or '').strip()
    if bool(token) != bool(domain):
        raise ValueError('ARGO_TOKEN 与 CUSTOM_DOMAIN 必须同时填写或同时留空')
    if domain and (not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain)
                   or domain.startswith('.') or domain.endswith('.')):
        raise ValueError('CUSTOM_DOMAIN 只填写域名，不含协议、端口或路径')
    uid = str(secret('UUID_STR', '') or '').strip() or str(saved.get('uuid') or '')
    uid = uid or str(uuid.uuid4())
    try:
        uuid.UUID(uid)
    except ValueError as exc:
        raise ValueError('UUID_STR 格式无效') from exc
    port = get_port(secret('PORT_VM_WS', ''), saved.get('port'))
    test_port = get_port(secret('TEST_PORT', ''), saved.get('test_port'))
    if port == test_port:
        raise ValueError('TEST_PORT 不能与 PORT_VM_WS 相同')
    protocol = str(secret('PROTOCOL', 'vless') or 'vless').lower().strip()
    if protocol not in ('vless', 'vmess', 'trojan'):
        raise ValueError('PROTOCOL 仅支持 vless/vmess/trojan')
    cfg = {'protocol': protocol, 'uuid': uid, 'port': port, 'test_port': test_port,
           'ws_path': '/' + str(secret('WS_PATH', '/') or '/').strip().lstrip('/'),
           'trojan_password': str(secret('TROJAN_PASSWORD', '') or ''),
           'vpn_user': str(secret('VPN_USER', 'vpn') or 'vpn'),
           'vpn_pass': str(secret('VPN_PASS', 'vpn') or 'vpn'),
           'token': token, 'domain': domain}
    write_private(RUNTIME, json.dumps({'uuid': uid, 'port': port, 'test_port': test_port}))
    return cfg


def parse_ovpn(text):
    if len(text.encode('utf-8')) > 150000:
        raise ValueError('.ovpn 文件超过 150 KB')
    opts, blocks, active, buf, user_pass = {}, {}, None, [], False
    for raw in text.replace('\r\n', '\n').splitlines():
        line = raw.strip()
        if active:
            if line == f'</{active}>':
                blocks[active] = '\n'.join(buf).strip() + '\n'
                active, buf = None, []
            else:
                buf.append(raw)
            continue
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('<'):
            tag = line[1:-1].lower() if line.endswith('>') else ''
            if tag not in BLOCKS or tag in blocks:
                raise ValueError('不支持或重复的内联块：' + line[:60])
            active, buf = tag, []
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ValueError('.ovpn 指令格式错误') from exc
        if not parts:
            continue
        key, args = parts[0].lower(), parts[1:]
        if key == 'auth-user-pass':
            if args:
                raise ValueError('不支持外部凭据文件')
            user_pass = True
        elif key == 'dev':
            if args != ['tun']:
                raise ValueError('仅支持 dev tun')
        elif key == 'remote-cert-tls':
            if args != ['server']:
                raise ValueError('仅支持 remote-cert-tls server')
        elif key == 'setenv':
            if len(args) < 2 or args[0] not in ('CLIENT_CERT', 'UV_DEVICE_ID'):
                raise ValueError('不支持的 setenv 参数')
        elif key in FIELDS:
            if key == 'remote' and key in opts:
                raise ValueError('仅支持单个 remote')
            opts[key] = args
        elif key not in IGNORE:
            raise ValueError('不支持的 .ovpn 指令：' + key)
    if active or not blocks.get('ca'):
        raise ValueError('缺少完整内联 <ca> 证书')
    if bool(blocks.get('cert')) != bool(blocks.get('key')):
        raise ValueError('<cert> 和 <key> 必须同时提供')
    remote = opts.get('remote', [])
    if len(remote) not in (2, 3):
        raise ValueError('remote 必须包含主机和端口')
    host = remote[0]
    if not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', host):
        raise ValueError('remote 主机格式无效')
    try:
        port = int(remote[1])
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError as exc:
        raise ValueError('remote 端口无效') from exc
    proto = (remote[2] if len(remote) == 3 else (opts.get('proto') or ['udp'])[0]).lower()
    network = {'tcp-client': 'tcp', 'tcp': 'tcp', 'udp': 'udp'}.get(proto)
    if not network:
        raise ValueError('仅支持 OpenVPN TCP/UDP')
    tls = {'certificate': [blocks['ca']], 'remote_certificate_tls': 'server'}
    if blocks.get('cert'):
        tls.update(client_certificate=[blocks['cert']], client_key=[blocks['key']])
    wraps = [k for k in ('tls-auth', 'tls-crypt', 'tls-crypt-v2') if blocks.get(k)]
    if len(wraps) > 1 or (opts.get('key-direction') and wraps != ['tls-auth']):
        raise ValueError('tls-auth/tls-crypt/key-direction 配置冲突')
    if wraps:
        tls['control_wrap'] = {'type': wraps[0].replace('-', '_'), 'key': [blocks[wraps[0]]]}
        if opts.get('key-direction'):
            direction = opts['key-direction'][0]
            if direction not in ('0', '1'):
                raise ValueError('key-direction 必须为 0 或 1')
            tls['control_wrap']['direction'] = 'client' if direction == '1' else 'server'
    ep = {'type': 'openvpn-client', 'tag': 'vpn-exit', 'mode': 'tls',
          'server': host, 'server_port': port, 'network': network,
          'system': False, 'tls': tls}
    for src, dest in (('auth', 'auth'), ('cipher', 'data_ciphers_fallback'),
                      ('data-ciphers-fallback', 'data_ciphers_fallback')):
        if opts.get(src):
            ep[dest] = opts[src][0]
    if opts.get('data-ciphers'):
        ep['data_ciphers'] = opts['data-ciphers'][0].split(':')
    if opts.get('tun-mtu'):
        ep['mtu'] = int(opts['tun-mtu'][0])
    if opts.get('reneg-sec'):
        ep['renegotiate_interval'] = opts['reneg-sec'][0] + 's'
    if opts.get('tls-version-min') and opts['tls-version-min'][0] != '1.2':
        raise ValueError('仅支持 tls-version-min 1.2')
    return ep, user_pass


def global_ipv4(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address) and addr.is_global
    except ValueError:
        return False


def fetch_candidates(country, limit):
    req = urllib.request.Request(API_URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=25) as response:
        final = urlparse(response.geturl())
        if final.scheme != 'https' or final.hostname not in ('www.vpngate.net', 'api.vpngate.net') or final.path != '/api/iphone/':
            raise ValueError('节点源不在 VPN Gate 官方 API 地址')
        raw = response.read(80_000_001)
    if len(raw) > 80_000_000:
        raise ValueError('CSV 超过 80 MB')
    content = raw.decode('utf-8-sig', errors='replace')
    pos = content.find('#HostName,IP,Score,Ping,Speed,')
    if pos < 0:
        raise ValueError('VPN Gate 未返回预期 CSV')
    rows = csv.DictReader(io.StringIO(content[pos + 1:]))
    if not {'IP', 'CountryShort', 'Speed', 'OpenVPN_ConfigData_Base64'}.issubset(rows.fieldnames or []):
        raise ValueError('CSV 字段不完整')
    result, seen = [], set()
    for row in rows:
        if len(result) >= limit:
            break
        if country != '全部' and (row.get('CountryShort') or '').upper() != country:
            continue
        ip = (row.get('IP') or '').strip()
        if not global_ipv4(ip):
            continue
        encoded = (row.get('OpenVPN_ConfigData_Base64') or '').strip()
        if row.get(None):
            encoded = row[None][-1].strip()
        if not 100 <= len(encoded) <= 200000:
            continue
        try:
            profile = base64.b64decode(encoded, validate=True).decode('utf-8-sig')
            ep, _ = parse_ovpn(profile)
            if ep['network'] != 'tcp':
                continue
            hostname = (row.get('HostName') or '').strip().lower().rstrip('.')
            remote = ep['server'].lower().rstrip('.')
            if remote != ip and remote not in (hostname, hostname + '.opengw.net'):
                continue
            identity = (ip, ep['server_port'])
            if identity in seen:
                continue
            seen.add(identity)
            result.append({'host': hostname or ip, 'ip': ip, 'port': ep['server_port'],
                           'country': row.get('CountryShort', ''),
                           'speed': round(max(0, int(row.get('Speed') or 0)) / 1e6, 1),
                           'ping': row.get('Ping', '?'), 'profile': profile,
                           'successes': 0, 'attempts': 0, 'handshake_ms': None,
                           'status': '未测试'})
        except (ValueError, UnicodeError, TypeError, IndexError, OverflowError):
            continue
    if not result:
        raise ValueError('没有兼容的 TCP OpenVPN 候选；换地区或手动上传 .ovpn')
    return result


def get_pid(path):
    try:
        value = int(path.read_text().strip())
        return value if value > 0 else None
    except (OSError, TypeError, ValueError, OverflowError):
        return None


def ours(number, binary):
    if not number:
        return False
    try:
        proc = Path('/proc') / str(number)
        return ((proc / 'exe').resolve(strict=True) == binary.resolve(strict=True)
                and not re.search(r'^State:\s+Z', (proc / 'status').read_text(), re.M))
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
    NODES.unlink(missing_ok=True)


def log_text(path):
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def download(url, target):
    HOME.mkdir(parents=True, exist_ok=True)
    tmp = HOME / ('.download-' + uuid.uuid4().hex)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=35) as src, tmp.open('wb') as dst:
            size = 0
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > 100_000_000:
                    raise RuntimeError('下载超过 100 MB')
                dst.write(chunk)
        tmp.replace(target)
    finally:
        tmp.unlink(missing_ok=True)


def ensure_singbox():
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    if platform.system() != 'Linux' or not arch:
        raise RuntimeError('仅支持 Linux amd64/arm64')
    version = None
    if SB_BIN.exists():
        try:
            version = subprocess.run([str(SB_BIN), 'version'], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not version or version.returncode or not version.stdout.splitlines() or SB_VERSION not in version.stdout.splitlines()[0]:
        folder = f'sing-box-{SB_VERSION}-linux-{arch}'
        archive = HOME / 'sing-box.tar.gz'
        download(f'https://github.com/SagerNet/sing-box/releases/download/v{SB_VERSION}/{folder}.tar.gz', archive)
        with tarfile.open(archive, 'r:gz') as tar:
            member = next((x for x in tar.getmembers() if x.name == folder + '/sing-box' and x.isfile()), None)
            if member is None:
                raise RuntimeError('sing-box 安装包内容异常')
            with tar.extractfile(member) as src, SB_BIN.open('wb') as dst:
                shutil.copyfileobj(src, dst)
        archive.unlink(missing_ok=True)
        SB_BIN.chmod(0o700)
    return arch


def ensure_binaries():
    arch = ensure_singbox()
    if not CF_BIN.exists():
        download(f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}', CF_BIN)
        CF_BIN.chmod(0o700)


def prepare_endpoint(profile, cfg):
    ep, needs_password = parse_ovpn(profile)
    if needs_password:
        ep['username'] = cfg['vpn_user']
        ep['password'] = cfg['vpn_pass']
    return ep


def test_one_handshake(item, cfg, timeout=12):
    """Isolated process; only OpenVPN handshake. Does not touch live service or third-party hosts."""
    ep = prepare_endpoint(item['profile'], cfg)
    HOME.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='probe-', dir=HOME) as directory:
        directory = Path(directory)
        config = directory / 'config.json'
        logfile = directory / 'log.txt'
        # A local inbound ensures the endpoint is initialized, but sends no traffic.
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            local_port = s.getsockname()[1]
        config.write_text(json.dumps({
            'log': {'level': 'info'},
            'inbounds': [{'type': 'socks', 'tag': 'probe', 'listen': '127.0.0.1',
                          'listen_port': local_port}],
            'endpoints': [ep], 'route': {'final': 'vpn-exit'}
        }), encoding='utf-8')
        config.chmod(0o600)
        checked = subprocess.run([str(SB_BIN), 'check', '-c', str(config)],
                                 capture_output=True, text=True, timeout=8)
        if checked.returncode:
            return None, '配置检查失败'
        process = None
        try:
            with logfile.open('w') as out:
                start = time.monotonic()
                process = subprocess.Popen([str(SB_BIN), 'run', '-c', str(config)],
                                           cwd=directory, stdout=out, stderr=subprocess.STDOUT)
            while time.monotonic() - start < timeout:
                text = ANSI.sub('', log_text(logfile)).lower()
                if 'tunnel established to ' in text:
                    return round((time.monotonic() - start) * 1000), '握手成功'
                if 'authentication failed' in text:
                    return None, '认证失败'
                if 'client terminated' in text:
                    return None, '握手失败'
                if process.poll() is not None:
                    return None, '测试进程退出'
                time.sleep(.15)
            return None, '握手超时'
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


def test_all(items, cfg, repeats, progress=None):
    """Every fetched candidate, sequentially; no parallel VPN handshakes."""
    total = len(items) * repeats
    completed = 0
    for item in items:
        times, failures = [], []
        for _ in range(repeats):
            try:
                elapsed, status = test_one_handshake(item, cfg)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                elapsed, status = None, '测试异常：' + type(exc).__name__
            if elapsed is not None:
                times.append(elapsed)
            else:
                failures.append(status)
            completed += 1
            if progress:
                progress(completed / total, f'测试 {completed}/{total}：{item["host"]}')
        item.update(attempts=repeats, successes=len(times),
                    handshake_ms=round(statistics.median(times)) if times else None,
                    status=('握手成功' if len(times) == repeats else
                            '部分成功：' + ', '.join(sorted(set(failures))) if times else
                            ', '.join(sorted(set(failures)))))
    items.sort(key=lambda x: (-x['successes'] / x['attempts'],
                              x['handshake_ms'] if x['handshake_ms'] is not None else float('inf')))
    return items


def make_config(cfg, ep):
    user = ({'password': cfg['trojan_password'] or cfg['uuid']} if cfg['protocol'] == 'trojan'
            else {'uuid': cfg['uuid']})
    if cfg['protocol'] == 'vmess':
        user['alterId'] = 0
    return {'log': {'level': 'info'},
            'inbounds': [{'type': cfg['protocol'], 'tag': 'client', 'listen': '127.0.0.1',
                          'listen_port': cfg['port'], 'users': [user],
                          'transport': {'type': 'ws', 'path': cfg['ws_path']}},
                         {'type': 'socks', 'tag': 'test', 'listen': '127.0.0.1',
                          'listen_port': cfg['test_port']}],
            'endpoints': [ep], 'route': {'final': 'vpn-exit'}}


def quick_domain(process):
    pattern = re.compile(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)')
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError('cloudflared 提前退出：' + log_text(CF_LOG)[-1500:])
        match = pattern.search(log_text(CF_LOG))
        if match:
            return match.group(1)
        time.sleep(.5)
    raise RuntimeError('完整 cloudflared 日志未发现临时域名：' + log_text(CF_LOG)[:1500])


def node_link(domain, cfg):
    query = urlencode({'security': 'tls', 'sni': domain, 'type': 'ws',
                       'host': domain, 'path': cfg['ws_path']})
    if cfg['protocol'] == 'vmess':
        obj = {'v': '2', 'ps': 'VPN Gate', 'add': domain, 'port': '443', 'id': cfg['uuid'],
               'aid': '0', 'scy': 'auto', 'net': 'ws', 'type': 'none', 'host': domain,
               'path': cfg['ws_path'], 'tls': 'tls', 'sni': domain}
        return 'vmess://' + base64.b64encode(json.dumps(obj).encode()).decode().rstrip('=')
    credential = cfg['uuid'] if cfg['protocol'] == 'vless' else cfg['trojan_password'] or cfg['uuid']
    if cfg['protocol'] == 'vless':
        query = 'encryption=none&' + query
    return f"{cfg['protocol']}://{quote(credential, safe='')}@{domain}:443?{query}#VPN-Gate"


def start_service(cfg):
    if not PROFILE.exists():
        raise ValueError('请先选择并保存节点，或手动上传 .ovpn')
    ep = prepare_endpoint(PROFILE.read_text(encoding='utf-8'), cfg)
    ensure_binaries()
    write_private(SB_CONF, json.dumps(make_config(cfg, ep), ensure_ascii=False, indent=2))
    check = subprocess.run([str(SB_BIN), 'check', '-c', str(SB_CONF)],
                           capture_output=True, text=True, timeout=25)
    if check.returncode:
        raise RuntimeError('sing-box 配置检查失败：' + (check.stderr or check.stdout)[-1500:])
    stop()
    try:
        with SB_LOG.open('w') as out:
            sb = subprocess.Popen([str(SB_BIN), 'run', '-c', str(SB_CONF)],
                                  cwd=HOME, stdout=out, stderr=subprocess.STDOUT)
        write_private(SB_PID, str(sb.pid))
        for _ in range(30):
            if sb.poll() is not None:
                raise RuntimeError('sing-box 提前退出：' + log_text(SB_LOG)[-1500:])
            try:
                with socket.create_connection(('127.0.0.1', cfg['port']), timeout=.3):
                    break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError('sing-box 本地入口未就绪：' + log_text(SB_LOG)[-1500:])
        if cfg['token']:
            cmd = [str(CF_BIN), 'tunnel', '--no-autoupdate', 'run', '--token', cfg['token']]
        else:
            cmd = [str(CF_BIN), 'tunnel', '--no-autoupdate', '--url',
                   f"http://127.0.0.1:{cfg['port']}", '--protocol', 'http2']
        with CF_LOG.open('w') as out:
            cf = subprocess.Popen(cmd, cwd=HOME, stdout=out, stderr=subprocess.STDOUT)
        write_private(CF_PID, str(cf.pid))
        domain = cfg['domain'] if cfg['token'] else quick_domain(cf)
        if cf.poll() is not None:
            raise RuntimeError('cloudflared 已退出：' + log_text(CF_LOG)[-1500:])
        if 'authentication failed' in log_text(SB_LOG).lower():
            raise RuntimeError('VPN 认证失败；检查 .ovpn 或更换节点')
        write_private(NODES, node_link(domain, cfg) + '\n')
        return domain
    except Exception:
        stop()
        raise


def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError('连接提前断开')
        data += chunk
    return data


def verify_exit(port):
    host = 'api.country.is'
    sock = socket.create_connection(('127.0.0.1', port), timeout=15)
    sock.settimeout(15)
    try:
        sock.sendall(b'\x05\x01\x00')
        if recv_exact(sock, 2) != b'\x05\x00':
            raise OSError('SOCKS 协商失败')
        name = host.encode('ascii')
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + (443).to_bytes(2, 'big'))
        reply = recv_exact(sock, 4)
        if reply[1] != 0:
            raise OSError('OpenVPN 出站尚未就绪，SOCKS 错误码 ' + str(reply[1]))
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = recv_exact(sock, 1)[0]
        if size is None:
            raise OSError('SOCKS 地址类型无效')
        recv_exact(sock, size + 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
            tls.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n'.encode())
            resp = http.client.HTTPResponse(tls)
            resp.begin()
            if resp.status != 200:
                raise OSError('出口查询 HTTP ' + str(resp.status))
            data = json.loads(resp.read(20000))
            if not data.get('ip'):
                raise OSError('出口查询未返回 IP')
            return data
    finally:
        sock.close()


def main():
    st.set_page_config(page_title='VPN Gate 连接质量测试', layout='wide')
    password = str(secret('SECRET_KEY', '') or '')
    if not password or password == 'your_secret_password_here':
        st.error('请在 Streamlit App settings -> Secrets 设置非默认 SECRET_KEY')
        return
    if not st.session_state.get('authenticated'):
        st.title('VPN Gate 管理登录')
        attempt = st.text_input('管理口令', type='password')
        if st.button('登录'):
            if hmac.compare_digest(attempt, password):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error('口令错误')
        return
    if st.sidebar.button('退出登录'):
        st.session_state.authenticated = False
        st.session_state.pop('candidates', None)
        st.rerun()
    st.title('VPN Gate 连接质量测试')
    try:
        cfg = settings()
    except Exception as exc:
        st.error('Secrets 配置错误：' + str(exc))
        return
    mode = '固定域名' if cfg['token'] else '临时隧道'
    st.caption(f'配置优先读取 Streamlit Secrets；入口模式：{mode}。只有你点击启动时才切换正式服务。')
    st.write('sing-box：', '运行中' if ours(get_pid(SB_PID), SB_BIN) else '未运行',
             '；cloudflared：', '运行中' if ours(get_pid(CF_PID), CF_BIN) else '未运行')
                  render_speed_test(
        st,
        cfg["test_port"],
        ours(get_pid(SB_PID), SB_BIN),
    )
    st.info('测试范围：Streamlit 容器到 VPN Gate 的 OpenVPN 握手。握手耗时不是 Mbps，也不包含客户端到 Cloudflare 或 VPN Gate 到网站。')
    col1, col2 = st.columns(2)
    country = col1.selectbox('国家/地区', ['JP', 'KR', 'US', '全部'])
    count = col2.slider('拉取的兼容候选数（全部逐一测试）', 5, 40, 20, step=5)
    repeats = st.selectbox('每个候选握手次数', [1, 2, 3], index=1)
    if st.button('拉取候选'):
        try:
            with st.spinner('读取 VPN Gate 清单...'):
                st.session_state.candidates = fetch_candidates(country, count)
            st.success(f'拉取了 {len(st.session_state.candidates)} 个兼容 TCP 候选；尚未启动测试。')
        except Exception as exc:
            st.session_state.pop('candidates', None)
            st.error('拉取失败：' + str(exc))
    items = st.session_state.get('candidates', [])
    if items and st.button('逐一测试全部已拉取候选的 OpenVPN 握手'):
        try:
            with st.spinner('逐一测试握手；正式服务不受影响...'):
                ensure_singbox()
                bar = st.progress(0.0)
                st.session_state.candidates = test_all(items, cfg, repeats, bar.progress)
            st.success('已完成全部已拉取候选的连接质量测试；不会自动添加或启动。')
        except Exception as exc:
            st.error('测试中断：' + str(exc))
    items = st.session_state.get('candidates', [])
    if items:
        st.dataframe([{'序号': i + 1, '节点': x['host'], '国家': x['country'],
                       '握手成功': f"{x['successes']}/{x['attempts']}" if x['attempts'] else '未测',
                       '成功握手中位耗时(ms)': x['handshake_ms'], '状态': x['status'],
                       '官网Speed(Mbps，非本机实测)': x['speed'],
                       '官网Ping(ms)': x['ping'], 'IP': x['ip'], '端口': x['port']}
                      for i, x in enumerate(items)], use_container_width=True, hide_index=True)
        indices = list(range(len(items)))
        selected = st.selectbox('手动选择候选', indices,
                                format_func=lambda i: f"{i + 1}. {items[i]['host']} / {items[i]['status']}")
        if st.button('添加所选节点（不启动）'):
            try:
                parse_ovpn(items[selected]['profile'])
                write_private(PROFILE, items[selected]['profile'])
                st.success('已保存 .ovpn；正在运行的服务不切换。由你点击启动/重启服务后生效。')
            except Exception as exc:
                st.error('添加失败：' + str(exc))
    upload = st.file_uploader('或手动上传 VPN Gate .ovpn', type=['ovpn'])
    if upload is not None and st.button('保存上传的 .ovpn（不启动）'):
        try:
            text = upload.getvalue().decode('utf-8-sig')
            parse_ovpn(text)
            write_private(PROFILE, text)
            st.success('已保存 .ovpn；不会自动启动。')
        except Exception as exc:
            st.error('.ovpn 不兼容：' + str(exc))
    if PROFILE.exists():
        try:
            ep, auth = parse_ovpn(PROFILE.read_text(encoding='utf-8'))
            st.info(f"已保存落地：{ep['server']}:{ep['server_port']} / {ep['network']}；账号认证：{'需要' if auth else '配置未要求'}")
        except Exception as exc:
            st.warning('已保存的 .ovpn 无效：' + str(exc))
    a, b, c = st.columns(3)
    if a.button('启动/重启服务', use_container_width=True):
        try:
            with st.spinner('检查配置并启动...'):
                domain = start_service(cfg)
            st.success('隧道域名：' + domain)
            st.info('启动进程不等于 VPN 已连通；请验证实际出口。')
        except Exception as exc:
            st.error('启动失败：' + str(exc))
    if b.button('验证实际出口', use_container_width=True):
        try:
            if not ours(get_pid(SB_PID), SB_BIN):
                raise RuntimeError('sing-box 未运行')
            data = verify_exit(cfg['test_port'])
            st.success(f"sing-box 出口 IP：{data['ip']}；地区代码：{data.get('country', '')}")
        except Exception as exc:
            st.error('验证失败：' + str(exc))
    if c.button('停止服务', use_container_width=True):
        stop()
        st.info('已停止本项目记录的进程。')
    if NODES.exists():
        st.subheader('节点链接')
        st.code(NODES.read_text(encoding='utf-8'))
    with st.expander('诊断日志'):
        for path in (SB_LOG, CF_LOG):
            st.write(path.name)
            st.code(log_text(path)[-3500:] or '无日志')



if __name__ == '__main__':
    main()
