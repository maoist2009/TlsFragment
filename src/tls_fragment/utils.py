from ipaddress import ip_address
import ipaddress
from .log import logger
import socket
import struct

logger = logger.getChild("utils")


def ip_to_binary_prefix(ip_or_network):
    try:
        network = ipaddress.ip_network(ip_or_network, strict=False)
        network_address = network.network_address
        prefix_length = network.prefixlen
        if isinstance(network_address, ipaddress.IPv4Address):
            binary_network = bin(int(network_address))[2:].zfill(32)
        elif isinstance(network_address, ipaddress.IPv6Address):
            binary_network = bin(int(network_address))[2:].zfill(128)
        binary_prefix = binary_network[:prefix_length]
        return binary_prefix
    except ValueError:
        try:
            ip = ipaddress.ip_address(ip_or_network)
            if isinstance(ip, ipaddress.IPv4Address):
                binary_ip = bin(int(ip))[2:].zfill(32)
                binary_prefix = binary_ip[:32]
            elif isinstance(ip, ipaddress.IPv6Address):
                binary_ip = bin(int(ip))[2:].zfill(128)
                binary_prefix = binary_ip[:128]
            return binary_prefix
        except ValueError:
            raise ValueError(f"输入 {ip_or_network} 不是有效的 IP 地址或网络")


def set_ttl(sock, ttl):
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)


def check_ttl(ip, port, ttl):
    try:
        if ip.find(":") != -1:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_ttl(sock, ttl)
        sock.settimeout(0.5)
        sock.connect((ip, port))
        sock.send(b"0")
        sock.close()
        return True
    except Exception as e:
        logger.warning(e)
        return False
    finally:
        sock.close()


def get_ttl(ip, port):
    l = 1
    r = 128
    ans = -1
    while l <= r:
        mid = (l + r) // 2
        val = check_ttl(ip, port, mid)
        logger.debug("%d %d %d %d %d", l, r, mid, ans, val)
        if val:
            ans = mid
            r = mid - 1
        else:
            l = mid + 1

    logger.info("get_ttl %s %d %d", ip, port, ans)
    return ans


def is_ip_address(s):
    if s.isdigit():
        return False  # Disallow integer-formatted IP addresses
    else:
        try:
            ip_address(s)
            return True
        except ValueError:
            return False


def extract_sni(data):
    """
    extract sni
    data: the tls data.
    """
    # 解析TLS记录
    content_type, _, _, length = struct.unpack(">BBBH", data[:5])
    if content_type != 0x16:  # 0x16表示TLS Handshake
        raise ValueError("Not a TLS Handshake message")
    handshake_data = data[5 : 5 + length]

    # 解析握手消息头
    handshake_type, tmp, length = struct.unpack(">BBH", handshake_data[:4])
    length = tmp * 64 + length
    if handshake_type != 0x01:  # 0x01表示Client Hello
        raise ValueError("Not a Client Hello message")
    client_hello_data = handshake_data[4 : 4 + length]

    # 解析Client Hello消息
    _, _, _, session_id_length = struct.unpack(">BB32sB", client_hello_data[:35])
    cipher_suites_length = struct.unpack(
        ">H", client_hello_data[35 + session_id_length : 35 + session_id_length + 2]
    )[0]
    compression_methods_length = struct.unpack(
        ">B",
        client_hello_data[
            35
            + session_id_length
            + 2
            + cipher_suites_length : 35
            + session_id_length
            + 2
            + cipher_suites_length
            + 1
        ],
    )[0]

    # 定位扩展部分
    extensions_offset = (
        35
        + session_id_length
        + 2
        + cipher_suites_length
        + 1
        + compression_methods_length
    )
    extensions_length = struct.unpack(
        ">H", client_hello_data[extensions_offset : extensions_offset + 2]
    )[0]
    extensions_data = client_hello_data[
        extensions_offset + 2 : extensions_offset + 2 + extensions_length
    ]

    offset = 0
    while offset < extensions_length:
        extension_type, extension_length = struct.unpack(
            ">HH", extensions_data[offset : offset + 4]
        )
        if extension_type == 0x0000:  # SNI扩展的类型是0x0000
            sni_extension = extensions_data[offset + 4 : offset + 4 + extension_length]
            # 解析SNI扩展
            list_length = struct.unpack(">H", sni_extension[:2])[0]
            if list_length != 0:
                name_type, name_length = struct.unpack(">BH", sni_extension[2:5])
                if name_type == 0:  # 域名类型
                    sni = sni_extension[5 : 5 + name_length]
                    return sni
        offset += 4 + extension_length
    return None

def parse_extensions(data):
    extensions = {}
    offset = 0
    try:
        while offset < len(data):
            if offset + 4 > len(data):
                break
            # 解析扩展类型
            ext_type = struct.unpack('>H', data[offset:offset + 2])[0]
            # 解析扩展长度
            ext_length = struct.unpack('>H', data[offset + 2:offset + 4])[0]
            if offset + 4 + ext_length > len(data):
                break
            # 解析扩展数据
            ext_data = data[offset + 4:offset + 4 + ext_length]
            extensions[ext_type] = ext_data
            offset += 4 + ext_length
    except struct.error as e:
        raise e
    return extensions


def detect_tls_version_by_keyshare(server_hello):
    # 解析TLS记录层
    if len(server_hello) < 5:
        return 0
    content_type, _, _, record_length = struct.unpack('>BBBH', server_hello[:5])
    if content_type != 0x16:  # 0x16表示TLS Handshake
        return 0
    handshake_data = server_hello[5:5 + record_length]

    # 解析握手消息头
    if len(handshake_data) < 4:
        return 0
    handshake_type, _, handshake_length = struct.unpack('>BBH', handshake_data[:4])
    if handshake_type != 0x02:  # 0x02表示Server Hello
        return 0

    # 跳过前面固定长度的字段（消息类型、长度、版本、随机数）
    offset = 4 + 2 + 32
    # 解析会话 ID 长度
    session_id_length = struct.unpack('>B', handshake_data[offset:offset + 1])[0]
    offset += 1 + session_id_length
    # 跳过密码套件和压缩方法
    offset += 2 + 1
    # 扩展字段起始位置
    extensions_start = offset

    # 解析扩展字段的总长度
    if extensions_start + 2 > len(handshake_data):
        return 0
    extensions_length = struct.unpack('>H', handshake_data[extensions_start:extensions_start + 2])[0]
    # 检查扩展字段数据是否完整
    if extensions_start + 2 + extensions_length > len(handshake_data):
        return 0
    # 提取扩展字段的数据
    extensions_data = handshake_data[extensions_start + 2:extensions_start + 2 + extensions_length]
    # 解析扩展字段
    extensions = parse_extensions(extensions_data)

    # 定义key_share扩展类型
    key_share_ext_type = 0x0033
    # 检查是否存在key_share扩展
    try:
        has_key_share_ext = key_share_ext_type in extensions

        if has_key_share_ext:
            return 1
        else:
            return -1
    except:
        return 0

