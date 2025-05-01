import struct


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
