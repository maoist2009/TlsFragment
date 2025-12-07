import ipaddress
import socket
import struct
from .log import logger
logger = logger.getChild("utils")

def expand_pattern(s):
    left_index, right_index = s.find('('), s.find(')')
    if left_index == -1 and right_index == -1:
        return s.split('|')
    if -1 in (left_index, right_index):
        raise ValueError("Both '(' and ')' must be present", s)
    if left_index > right_index:
        raise ValueError("'(' must occur before ')'", s)
    if right_index == left_index + 1:
        raise ValueError(
            'A vaild string should exist between a pair of parentheses', s
        )
    prefix = s[:left_index]
    suffix = s[right_index + 1:]
    inner = s[left_index + 1:right_index]
    return [prefix + part + suffix for part in inner.split('|')]


def ip_to_binary_prefix(ip_or_network:str):
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
            raise ValueError(f"input {ip_or_network} is not a valid IP or network address")


def calc_redirect_ip(ip_str:str, mapper_str:str):
    # 自动补全默认前缀
    if '/' not in mapper_str:
        if ':' in mapper_str:
            mapper_str += '/128'  # IPv6 默认 /128
        else:
            mapper_str += '/32'   # IPv4 默认 /32

    # 解析目标网络
    mapper_network = ipaddress.ip_network(mapper_str, strict=False)

    # 解析源 IP 地址
    ip_obj = ipaddress.ip_address(ip_str)

    # 根据 mapper 的地址族确定地址长度
    if mapper_network.version == 4:
        total_bits = 32
        address_class = ipaddress.IPv4Address
    else:
        total_bits = 128
        address_class = ipaddress.IPv6Address

    prefixlen = mapper_network.prefixlen
    fill_bits = total_bits - prefixlen

    # 构建掩码
    mask_fill = (1 << fill_bits) - 1
    mask_keep = ((1 << total_bits) - 1) ^ mask_fill

    # 获取源 IP 的整数表示
    ip_int = int(ip_obj)

    # 获取目标网络地址的整数表示
    mapped_network_int = int(mapper_network.network_address)

    # 计算填充部分
    fill_part = ip_int & mask_fill

    # 合成新的 IP 地址整数
    new_int = (mapped_network_int & mask_keep) | fill_part

    # 构造新的 IP 地址对象
    return str(address_class(new_int))

def is_ip_address(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def fake_ttl_mapping(config, dist):
    if not config.startswith('q'):
        return int(config)
    items = config[1:].split(';')
    intervals = []
    for item in items:
        if '-' in item:
            a, b = map(int, item.split('-'))
            intervals.append((a, '-', b))  # a-b
        elif '=' in item:
            a, val = map(int, item.split('='))
            intervals.append((a, '=', val))  # a=b

    intervals.sort(reverse=True, key=lambda x: x[0])

    for a, typ, val in intervals:
        if dist >= a:
            if typ == '-':
                return dist - val
            elif typ == '=':
                return val
    raise ValueError

def set_ttl(sock, ttl):
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)


def check_ttl(ip, port, ttl):
    try:
        if ':' in ip:
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
        logger.warning(f'check_ttl error: {repr(e)}')
        return False
    finally:
        sock.close()


def get_ttl(ip, port):
    l = 1
    r = 32
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


def detect_tls_version_by_keyshare(data):
    '''
    Validate the existence of "key_share" in ClientHello.
    '''
    try:
        if len(data) < 5: # Not long enough
            return 0

        # Parse TLS record layer header:
        # 1-byte type, 2-type version, 2-type length.
        record_type, record_version, record_length = struct.unpack('!BHH', data[:5])

        # Check if it is a Handshake (type 22) and data length is sufficient.
        if record_type != 22 or len(data) < 5 + record_length:
            return 0

        # Extract Handshake protocol data (excluding record layer header).
        handshake_data = data[5:5+record_length]
        if len(handshake_data) < 4:  # Handshake header must be at least 4 bytes.
            return 0

         # Parse Handshake header: 1-byte type, 3-byte length.
        handshake_type = handshake_data[0]
        handshake_len = (handshake_data[1] << 16) | (handshake_data[2] << 8) | handshake_data[3]

        # Verify it is a ClientHello (type 1) and length matches.
        if handshake_type != 1 or len(handshake_data) < 4 + handshake_len:
            return 0

        # Extract ClientHello body (excluding Handshake header).
        hello_body = handshake_data[4:4+handshake_len]
        offset = 0

        # Skip fixed fields: protocol version (2 bytes) + random (32 bytes).
        if len(hello_body) < 34:
            return 0
        offset += 34  # 2 + 32
        
        # Parse and skip session ID.
        if offset >= len(hello_body):
            return 0
        session_id_len = hello_body[offset]
        offset += 1
        if offset + session_id_len > len(hello_body):
            return 0
        offset += session_id_len
        
        # Parse and skip cipher suites.
        if offset + 2 > len(hello_body):
            return 0
        cipher_suites_len = (hello_body[offset] << 8) | hello_body[offset+1]
        offset += 2
        if offset + cipher_suites_len > len(hello_body):
            return 0
        offset += cipher_suites_len
        
        # Parse and skip compression methods.
        if offset >= len(hello_body):
            return 0
        compression_len = hello_body[offset]
        offset += 1
        if offset + compression_len > len(hello_body):
            return 0
        offset += compression_len
        
        # Check if there are extensions length.
        if offset == len(hello_body):
            return -1  # No extensions.
        if offset + 2 > len(hello_body):
            return 0
        
        # Parse total extensions length.
        extensions_len = (hello_body[offset] << 8) | hello_body[offset+1]
        offset += 2
        if offset + extensions_len > len(hello_body):
            return 0
        
        # Traverse through extensions.
        end_ext = offset + extensions_len
        while offset < end_ext:
            # Each extension must have at least a 4-byte header.
            if offset + 4 > end_ext:
                return 0
            ext_type = (hello_body[offset] << 8) | hello_body[offset+1]
            ext_len = (hello_body[offset+2] << 8) | hello_body[offset+3]
            offset += 4
            
            # Check for `key_share` (extension type 51).
            if ext_type == 51:
                return 1
            
            # Skip over extension data.
            offset += ext_len
            if offset > end_ext:
                return 0
        
        return -1
    except Exception:
        return 0
    
def generate_tls_alert(data):
    '''Send fake TLS Alert message to the client'''
    record_type, version_major, version_minor, record_length = struct.unpack('!BBBH', data[:5])
    alert_type = 0x15
    alert_level = 0x02  # Fatal level
    alert_description = 0x46
    alert_payload = bytes((alert_level, alert_description))
    record_header = struct.pack(
        ">BHH",
        alert_type,
        (version_major << 8) | version_minor,
        len(alert_payload)
    )
    return record_header + alert_payload

def generate_302(data,domain):
    lines = data.decode().split("\r\n")
    request_line = lines[0].split()
    q_method, q_url = request_line[0], request_line[1]
    
    # 提取Host头
    host = None
    for line in lines[1:]:
        if line.lower().startswith('host:'):
            host = line.split(':', 1)[1].strip()
            break
    
    # 构建完整的HTTPS URL
    if q_url.startswith('http://'):
        https_url = q_url.replace("http://", "https://", 1)
    elif q_url.startswith('/'):
        # 相对路径，需要结合Host头
        if host:
            https_url = f"https://{host}{q_url}"
        else:
            https_url = f"https://{domain}{q_url}"
    else:
        # 其他情况（相对路径无/前缀）
        if host:
            https_url = f"https://{host}/{q_url}"
        else:
            https_url = f"https://{domain}/{q_url}"
            return
        
    logger.info(f"重定向 {q_method} 到 HTTPS: {https_url}")

    # 正确的302重定向响应
    response = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: {https_url}\r\n"
        f"Content-Length: 0\r\n"
        f"Proxy-agent: MyProxy/1.0\r\n"
        f"\r\n"
    )
    logger.debug(response)
    return response

def is_udp_dns_query(data):
    if len(data) < 12:
        return False
    flags = data[2:4]  # 取出第3和第4字节
    qr = flags[0] >> 7  # 取出QR位
    return qr == 0  # QR位为0表示查询
    
import dns.message
import dns.rrset
import dns.rdatatype

def fake_udp_dns_query(query):
    dns_query = dns.message.from_wire(query)

    # 创建DNS响应
    response = dns.message.make_response(dns_query)

    # 检查查询类型
    for question in dns_query.question:
        if question.rdtype == dns.rdatatype.A:
            # A记录返回127.0.0.1
            a_record = dns.rrset.from_text(question.name, 3600,"IN", "A", "127.0.0.114")
            response.answer.append(a_record)
        elif question.rdtype == dns.rdatatype.AAAA:
            # AAAA记录返回::1
            aaaa_record = dns.rrset.from_text(question.name, 3600,"IN" , "AAAA", "::114")
            
            response.answer.append(aaaa_record)
        else:
            # 其他记录返回未找到
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response

    return response.to_wire()
    
def parse_socks5_address(sock):
        """SOCKS5地址解析"""
        atyp=sock.recv(1)[0]
        if atyp == 0x01:  # IPv4
            server_ip = socket.inet_ntop(socket.AF_INET, sock.recv(4))
            return server_ip, int.from_bytes(sock.recv(2), "big")
        elif atyp == 0x03:  # 域名
            domain_len = ord(sock.recv(1))
            server_name = sock.recv(domain_len).decode()
            port = int.from_bytes(sock.recv(2), "big")
            return server_name, port
        elif atyp == 0x04:  # IPv6
            server_ip = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
            return server_ip, int.from_bytes(sock.recv(2), "big")
        raise ValueError("Invalid address type")

def parse_socks5_address_from_data(data):
    """SOCKS5 address parsing with error handling"""
    offset = 0
    atyp = data[offset:offset+1][0]
    offset += 1
    
    if atyp == 0x01:  # IPv4
        if len(data) < offset + 6:  # 4 bytes for IP + 2 bytes for port
            raise ValueError("Data too short for IPv4 address")
        server_ip = socket.inet_ntop(socket.AF_INET, data[offset:offset + 4])
        offset += 4
        port = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        return server_ip, port, offset
    elif atyp == 0x03:  # Domain name
        if len(data) < offset + 1:  # At least 1 byte for domain length
            raise ValueError("Data too short for domain length")
        domain_len = data[offset]
        offset += 1
        if len(data) < offset + domain_len + 2:  # domain + 2 bytes for port
            raise ValueError("Data too short for domain address")
        server_name = data[offset:offset + domain_len].decode()
        offset += domain_len
        port = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        return server_name, port, offset
    elif atyp == 0x04:  # IPv6
        if len(data) < offset + 18:  # 16 bytes for IP + 2 bytes for port
            raise ValueError("Data too short for IPv6 address")
        server_ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
        port = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        return server_ip, port, offset
    raise ValueError("Invalid address type")

def build_socks5_address(ip, port):
    """根据 IP 和端口构造 SOCKS5 地址"""
    # 解析 IP 地址
    try:
        packed_ip = socket.inet_pton(socket.AF_INET, ip)  # IPv4
        atyp = 0x01  # 地址类型为 IPv4
    except socket.error:
        try:
            packed_ip = socket.inet_pton(socket.AF_INET6, ip)  # IPv6
            atyp = 0x04  # 地址类型为 IPv6
        except socket.error:
            # 如果都无法解析，抛出异常
            raise ValueError("Invalid IP address format")

    # 构造 SOCKS5 地址
    return bytes([atyp]) + packed_ip + port.to_bytes(2, 'big')

def build_socks5_udp_ans(address,port,data):
    addr=build_socks5_address(address,port)
    hdr_len=len(addr)+3
    msg_len=len(data)+hdr_len
    return msg_len.to_bytes(2,'big')+hdr_len.to_bytes(1,'big')+addr+data

def find_second_last_dot(data: bytes) -> int:
    """
    查找 bytes 对象中倒数第二个 b'.' 的位置
    
    参数:
    data -- 要搜索的 bytes 对象
    
    返回:
    倒数第二个 b'.' 的索引位置，如果不足两个点则返回 -1
    """
    # 先找到最后一个点的位置
    last_dot = data.rfind(b'.')
    if last_dot == -1:
        return -1  # 没有任何点
    
    # 在最后一个点之前的部分查找倒数第二个点
    return data.rfind(b'.', 0, last_dot)