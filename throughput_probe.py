"""Bounded Streamlit egress benchmark through the running sing-box SOCKS inbound.

Use render_speed_test(st, test_port, service_running) inside the authenticated
part of app.py. No external Python dependencies, no node switching.
"""
import http.client
import socket
import ssl
import statistics
import time
import uuid

HOST = "speed.cloudflare.com"
MAX_BYTES = 8 * 1024 * 1024
MAX_SECONDS = 30


def _read_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("SOCKS 连接提前断开")
        data += chunk
    return data


def _open_via_socks(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=12)
    sock.settimeout(12)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _read_exact(sock, 2) != b"\x05\x00":
            raise OSError("本地 SOCKS 无认证协商失败")
        name = HOST.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        answer = _read_exact(sock, 4)
        if answer[:1] != b"\x05" or answer[1] != 0:
            raise OSError("VPN 出站未就绪，SOCKS 错误码 " + str(answer[1]))
        if answer[3] == 1:
            length = 4
        elif answer[3] == 4:
            length = 16
        elif answer[3] == 3:
            length = _read_exact(sock, 1)[0]
        else:
            raise OSError("SOCKS 响应地址类型错误")
        _read_exact(sock, length + 2)
        return sock
    except Exception:
        sock.close()
        raise


def download_once(via_vpn, test_port, byte_count=MAX_BYTES):
    """One HTTPS download, with fixed host and bounded transfer; no redirects."""
    if not 1 <= byte_count <= MAX_BYTES:
        raise ValueError("下载大小超出限制")
    if not 1 <= int(test_port) <= 65535:
        raise ValueError("本地 SOCKS 端口无效")
    begin = time.monotonic()
    sock = _open_via_socks(int(test_port)) if via_vpn else socket.create_connection((HOST, 443), timeout=12)
    sock.settimeout(12)
    try:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=HOST) as tls:
            tls.settimeout(12)
            path = f"/__down?bytes={byte_count}&cacheBust={uuid.uuid4().hex}"
            request = (f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
                       "Accept-Encoding: identity\r\nCache-Control: no-store\r\n"
                       "Connection: close\r\n\r\n")
            tls.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            first_byte_seconds = time.monotonic() - begin
            if response.status != 200:
                raise OSError(f"测速源返回 HTTP {response.status}；未计算速度")
            if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
                raise OSError("测速响应被压缩，结果无效")
            received = 0
            while received < byte_count:
                if time.monotonic() - begin > MAX_SECONDS:
                    raise TimeoutError("测速超时，未完成下载")
                chunk = response.read(min(65536, byte_count - received))
                if not chunk:
                    raise OSError(f"响应提前结束：仅收到 {received} 字节")
                received += len(chunk)
            total_seconds = time.monotonic() - begin
            # End-to-end per-request throughput includes TCP/TLS setup and TTFB.
            return {"mbps": round(received * 8 / total_seconds / 1e6, 2),
                    "ttfb_ms": round(first_byte_seconds * 1000),
                    "seconds": round(total_seconds, 2), "bytes": received}
    finally:
        sock.close()


def compare(test_port, byte_count=MAX_BYTES, rounds=2):
    if rounds not in (1, 2):
        raise ValueError("仅支持 1 或 2 轮")
    results = {"direct": [], "vpn": [], "errors": []}
    for _ in range(rounds):
        for mode in ("direct", "vpn"):
            try:
                results[mode].append(download_once(mode == "vpn", test_port, byte_count))
            except (OSError, TimeoutError, ValueError, ssl.SSLError) as exc:
                results["errors"].append(f"{mode}: {type(exc).__name__}: {exc}")
    for mode in ("direct", "vpn"):
        values = results[mode]
        results[mode + "_median_mbps"] = round(statistics.median(x["mbps"] for x in values), 2) if values else None
    return results


def render_speed_test(st, test_port, service_running):
    st.subheader("容器出站实际下载对照")
    st.caption("同一测速源：容器直连与容器经当前 VPN Gate 出站。包含 VPN Gate 到测速源，不包含本地客户端到 Cloudflare。")
    if st.button("测速：直连与当前 VPN 出站", disabled=not service_running, key="egress_throughput_button"):
        try:
            with st.spinner("正在下载限量测试数据..."):
                st.session_state["egress_throughput_result"] = compare(int(test_port))
                st.session_state["egress_throughput_port"] = int(test_port)
        except Exception as exc:
            st.error(f"测速失败：{type(exc).__name__}: {exc}")
    result = st.session_state.get("egress_throughput_result")
    if result:
        if not service_running or st.session_state.get("egress_throughput_port") != int(test_port):
            st.warning("这是此前的测速结果；当前服务已停止或端口已改变，请重新测速。")
        direct, vpn = result["direct_median_mbps"], result["vpn_median_mbps"]
        st.write(f"容器直连：{direct if direct is not None else '失败'} Mbps；"
                 f"经当前 VPN Gate：{vpn if vpn is not None else '失败'} Mbps")
        if result["errors"]:
            st.warning("；".join(result["errors"]))
        st.caption("每条路径最多两次、每次 8 MiB；切换或重启 VPN 后请重新测速。这是单连接短时下载对照，不是服务器带宽上限。")
