import socket
import struct
import os
import sys
import asyncio
import re

# 从环境变量读取配置，默认值适配LeapCell
PORT = int(os.getenv("SOCKS5_PORT", 80))  # 与LeapCell的Serving Port一致
MAX_CONN = int(os.getenv("SOCKS5_MAX_CONN", 100))

# 处理SOCKS5客户端（接收已读取的首个字节，无认证模式）
async def handle_client(client_socket, first_byte):
    loop = asyncio.get_running_loop()

    try:
        # SOCKS5协商阶段：首个字节已读取，直接使用
        ver = ord(first_byte)
        if ver != 5:
            print(f"[错误] 非SOCKS5协议，版本号：{ver}")
            await loop.sock_sendall(client_socket, b"\x05\xFF")
            return
        
        # 读取支持的认证方法数量
        nmethods_data = await loop.sock_recv(client_socket, 1)
        if len(nmethods_data) < 1:
            print("[错误] 未接收到认证方法数量")
            return
        nmethods = nmethods_data[0]
        
        # 读取客户端支持的认证方法
        methods = await loop.sock_recv(client_socket, nmethods)
        if 0x00 in methods:
            # 仅支持无认证模式（0x00），返回确认
            await loop.sock_sendall(client_socket, b"\x05\x00")
            print("[协商] 客户端选择无认证模式，协商成功")
        else:
            # 无支持的认证方式，拒绝连接
            await loop.sock_sendall(client_socket, b"\x05\xFF")
            print(f"[错误] 客户端不支持无认证模式，提交的方法：{methods}")
            return

        # SOCKS5请求阶段：读取客户端的请求头
        header = await loop.sock_recv(client_socket, 4)
        if len(header) < 4:
            print("[错误] 未接收到请求头")
            return
        ver, cmd, rsv, atyp = struct.unpack("!BBBB", header)
        print(f"[请求] 客户端请求命令：{cmd}（1=TCP转发，3=UDP转发），地址类型：{atyp}")

        # 解析目标地址和端口
        addr = ""
        port = 0
        if atyp == 1:
            # IPv4地址解析
            ip_data = await loop.sock_recv(client_socket, 4)
            if len(ip_data) < 4:
                print("[错误] IPv4地址数据不完整")
                return
            addr = socket.inet_ntoa(ip_data)
            port_data = await loop.sock_recv(client_socket, 2)
            if len(port_data) < 2:
                print("[错误] IPv4端口数据不完整")
                return
            port = struct.unpack("!H", port_data)[0]
        elif atyp == 3:
            # 域名解析
            domain_len_data = await loop.sock_recv(client_socket, 1)
            if len(domain_len_data) < 1:
                print("[错误] 域名长度数据不完整")
                return
            domain_len = domain_len_data[0]
            domain = (await loop.sock_recv(client_socket, domain_len)).decode('utf-8', errors='ignore')
            addr = domain
            port_data = await loop.sock_recv(client_socket, 2)
            if len(port_data) < 2:
                print("[错误] 域名端口数据不完整")
                return
            port = struct.unpack("!H", port_data)[0]
        elif atyp == 4:
            # IPv6地址解析（简化支持）
            ip6_data = await loop.sock_recv(client_socket, 16)
            if len(ip6_data) < 16:
                print("[错误] IPv6地址数据不完整")
                return
            addr = socket.inet_ntop(socket.AF_INET6, ip6_data)
            port_data = await loop.sock_recv(client_socket, 2)
            if len(port_data) < 2:
                print("[错误] IPv6端口数据不完整")
                return
            port = struct.unpack("!H", port_data)[0]
        else:
            print(f"[错误] 不支持的地址类型：{atyp}")
            return
        print(f"[目标] 客户端请求访问：{addr}:{port}")

        # 处理CONNECT命令（TCP转发，核心功能）
        if cmd == 1:
            try:
                # 解析目标地址并建立TCP连接
                infos = await loop.getaddrinfo(addr, port, type=socket.SOCK_STREAM)
                family, type_, proto, canonname, sockaddr = infos[0]
                remote_sock = socket.socket(family, type_, proto)
                remote_sock.setblocking(False)
                await loop.sock_connect(remote_sock, sockaddr)
                print(f"[TCP] 成功连接到目标服务器 {addr}:{port}")

                # 构造SOCKS5响应包：通知客户端连接成功
                bind_addr = remote_sock.getsockname()
                if family == socket.AF_INET:
                    bind_ip = socket.inet_aton(bind_addr[0])
                    bind_port = bind_addr[1]
                    reply = struct.pack("!BBBBIH", 5, 0, 0, 1, struct.unpack("!I", bind_ip)[0], bind_port)
                else:
                    # IPv6响应包构造
                    reply = struct.pack("!BBBB", 5, 0, 0, 4) + socket.inet_pton(socket.AF_INET6, bind_addr[0]) + struct.pack("!H", bind_addr[1])
                await loop.sock_sendall(client_socket, reply)
                print("[响应] 已通知客户端连接成功，开始转发数据")

                # 双向数据转发
                await forward_data(client_socket, remote_sock)
            except Exception as e:
                error_msg = f"[TCP] 连接目标服务器失败：{e}"
                print(error_msg)
                # 发送连接失败响应包
                fail_reply = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
                await loop.sock_sendall(client_socket, fail_reply)
                client_socket.close()
                return
        # 处理UDP ASSOCIATE命令（UDP转发，可选功能）
        elif cmd == 3:
            try:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.setblocking(False)
                udp_sock.bind(('0.0.0.0', 0))
                udp_port = udp_sock.getsockname()[1]
                print(f"[UDP] 启动UDP中继，监听端口：{udp_port}")

                # 构造UDP响应包
                udp_reply = struct.pack("!BBBBIH", 5, 0, 0, 1, 0, udp_port)
                await loop.sock_sendall(client_socket, udp_reply)

                # 启动UDP中继
                client_socket.close()
                await udp_associate(udp_sock)
            except Exception as e:
                print(f"[UDP] 启动中继失败：{e}")
                client_socket.close()
                return
        else:
            # 不支持的命令
            print(f"[错误] 不支持的请求命令：{cmd}")
            un_support_reply = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
            await loop.sock_sendall(client_socket, un_support_reply)
            client_socket.close()
            return
           
    except Exception as e:
        print(f"[错误] 客户端处理异常：{str(e)}")
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        client_socket.close()

# 处理HTTP健康检查请求（适配LeapCell）
async def handle_http(client_socket, first_byte):
    loop = asyncio.get_running_loop()
    try:
        # 读取剩余的HTTP请求数据
        data = first_byte + await loop.sock_recv(client_socket, 1023)
        request = data.decode('utf-8', errors='ignore')
        # 匹配LeapCell的健康检查路径
        if re.search(r"/kaithheathcheck|/kaithheat", request, re.IGNORECASE):
            # 返回200响应，通过健康检查
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
            await loop.sock_sendall(client_socket, response)
            print("[健康检查] LeapCell检测通过，返回200 OK")
        else:
            # 其他HTTP请求返回404
            response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
            await loop.sock_sendall(client_socket, response)
    except Exception as e:
        print(f"[HTTP] 健康检查处理异常：{e}")
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        client_socket.close()

# TCP数据双向转发核心函数
async def forward(src, dst, loop):
    try:
        while True:
            data = await loop.sock_recv(src, 4096)
            if not data:
                print(f"[转发] 源端 {src.getsockname()} 无数据，关闭连接")
                break
            # 打印转发数据长度（避免刷屏，不打印具体内容）
            print(f"[转发] 发送 {len(data)} 字节数据")
            await loop.sock_sendall(dst, data)
    except Exception as e:
        print(f"[转发] 数据传输异常：{e}")

# 管理双向转发任务
async def forward_data(sock1, sock2):
    loop = asyncio.get_running_loop()
    task1 = asyncio.create_task(forward(sock1, sock2, loop))
    task2 = asyncio.create_task(forward(sock2, sock1, loop))
    await asyncio.gather(task1, task2, return_exceptions=True)

    # 关闭套接字
    for s in (sock1, sock2):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except:
            pass
        s.close()
    print("[转发] 双向连接已关闭")

# UDP数据中继函数（可选功能）
async def udp_associate(udp_sock):
    loop = asyncio.get_running_loop()
    try:
        while True:
            data, client_addr = await loop.sock_recvfrom(udp_sock, 65535)
            if len(data) < 4:
                continue
            # 解析SOCKS5 UDP头
            rsv, frag, atyp = struct.unpack("!HBB", data[:4])
            if frag != 0:
                continue

            # 解析目标地址
            dst_ip = ""
            dst_port = 0
            payload = b""
            if atyp == 1:
                if len(data) < 10:
                    continue
                dst_ip = socket.inet_ntoa(data[4:8])
                dst_port = struct.unpack("!H", data[8:10])[0]
                payload = data[10:]
            elif atyp == 3:
                if len(data) < 7:
                    continue
                domain_len = data[4]
                if len(data) < 7 + domain_len:
                    continue
                dst_ip = data[5:5+domain_len].decode('utf-8', errors='ignore')
                dst_port = struct.unpack("!H", data[5+domain_len:7+domain_len])[0]
                payload = data[7+domain_len:]
            else:
                continue

            if not payload:
                continue

            # 转发UDP数据
            remote_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            remote_udp.sendto(payload, (dst_ip, dst_port))
            # 接收响应
            remote_udp.settimeout(2)
            try:
                resp_data, _ = remote_udp.recvfrom(65535)
                # 封装响应并返回给客户端
                resp_packet = b'\x00\x00\x01' + socket.inet_aton(dst_ip) + struct.pack('!H', dst_port) + resp_data
                await loop.sock_sendto(udp_sock, resp_packet, client_addr)
                print(f"[UDP] 转发 {len(payload)} 字节，响应 {len(resp_data)} 字节")
            except socket.timeout:
                print(f"[UDP] 目标 {dst_ip}:{dst_port} 超时无响应")
                continue
            finally:
                remote_udp.close()
    except Exception as e:
        print(f"[UDP] 中继异常：{e}")
    finally:
        udp_sock.close()

# 主函数：协议分流（SOCKS5/HTTP）+ 服务启动
async def main():
    # 创建TCP服务器
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setblocking(False)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(('0.0.0.0', PORT))
        server_sock.listen(MAX_CONN)
        print(f"[启动] SOCKS5代理（无认证模式）+HTTP健康检查运行在 0.0.0.0:{PORT} (LeapCell部署)")
        print(f"[提示] 客户端无需输入账号密码，直接连接即可")
    except Exception as e:
        print(f"[错误] 端口绑定失败：{e}")
        sys.exit(1)

    loop = asyncio.get_running_loop()
    while True:
        try:
            client_socket, client_addr = await loop.sock_accept(server_sock)
            print(f"\n[连接] 新客户端接入：{client_addr}")
            client_socket.setblocking(False)
            # 读取首个字节，识别协议类型
            first_byte = await loop.sock_recv(client_socket, 1)
            if not first_byte:
                client_socket.close()
                print(f"[连接] 客户端 {client_addr} 无数据，关闭连接")
                continue
            if first_byte == b'\x05':
                # SOCKS5协议：0x05是SOCKS5的版本号
                asyncio.create_task(handle_client(client_socket, first_byte))
            else:
                # HTTP协议：首个字节是GET/POST等字母
                asyncio.create_task(handle_http(client_socket, first_byte))
        except Exception as e:
            print(f"[错误] 接受连接异常：{e}")
            continue

if __name__ == "__main__":
    asyncio.run(main())
