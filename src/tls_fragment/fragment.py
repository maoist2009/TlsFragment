"""
tls data fragment.
"""

import time
import socket
import random
import struct
from tls_fragment.log import logger

logger = logger.getChild("fragment")

def fragment_content(data: str, num: int) -> list:
    """
    frag <data> into num pieces
    """
    data_lenth = len(data)
    fragmented_content = []
    if len(data) > 1:
        dividing_points = random.sample(
            range(1, data_lenth - 1), min(num, data_lenth - 1)
        )
    else:
        fragmented_content.append(data)
        return
    dividing_points.append(0)
    dividing_points.append(data_lenth)
    dividing_points.sort()
    for i in range(0, len(dividing_points) - 1):
        fragmented_content.append(data[dividing_points[i] : dividing_points[i + 1]])
    return fragmented_content


def fragment_pattern(data, pattern, num):
    """
    fragment pattern into at least num parts.
    the first part of the pattern contains in
    fragmented_data[0]
    """
    fragmented_data = []
    position = data.find(pattern)
    logger.debug("%s %s", pattern, position)
    if position == -1:
        fragmented_data.append(data)
        return fragmented_data
    pattern_lenth = len(pattern)
    data_lenth = len(data)

    fragmented_data.append(data[0:position])

    lenth = pattern_lenth // num
    if pattern_lenth % num != 0:
        lenth += 1

    for i in range(0, num):
        fragmented_data.append(
            data[position + i * lenth : position + min((i + 1) * lenth, pattern_lenth)]
        )

    fragmented_data.append(data[position + pattern_lenth : data_lenth])
    return fragmented_data


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


class FragSock(socket.socket):
    """
    sending data after fragged.
    """

    num_of_pieccs_tls: int
    num_of_pieccs_tcp: int
    send_interval: int

    def __init__(
        self,
        socket_family=-1,
        socket_type=-1,
        socket_proto=-1,
        socket_fileno=None,
        num_of_pieccs_tls=4,
        num_of_pieccs_tcp=4,
        send_interval=0.1,
    ):
        super().__init__(
            family=socket_family,
            type=socket_type,
            proto=socket_proto,
            fileno=socket_fileno,
        )
        self.num_of_pieccs_tls = num_of_pieccs_tls
        self.num_of_pieccs_tcp = num_of_pieccs_tcp
        self.send_interval = send_interval

    def sendall(self, data):
        try:
            sni = extract_sni(data)
        except ValueError:
            super().sendall(data)
            return
        logger.info("To send: %d Bytes.", len(data))
        if sni is None:
            super().sendall(data)
            return

        logger.debug("sending:    %s", data)
        base_header = data[:3]
        record = data[5:]

        fragmented_tls_data = fragment_pattern(record, sni, self.num_of_pieccs_tls)
        tcp_data = b""
        for i, _ in enumerate(fragmented_tls_data):
            fragmented_tls_data[i] = (
                base_header
                + int.to_bytes(len(fragmented_tls_data[i]), byteorder="big", length=2)
                + fragmented_tls_data[i]
            )
            tcp_data += fragmented_tls_data[i]
            logger.info("adding frag: %d bytes.", len(fragmented_tls_data[i]))
            logger.debug("adding frag: %s", fragmented_tls_data[i])

        logger.info("TLS fraged: %d Bytes.", len(tcp_data))
        logger.debug("TLS fraged: %s", tcp_data)

        fragmented_tcp_data = fragment_pattern(
            tcp_data,
            tcp_data[
                len(fragmented_tls_data[0]) : len(tcp_data)
                - len(fragmented_tls_data[-1])
                + 1
            ],
            self.num_of_pieccs_tcp,
        )

        for packet in fragmented_tcp_data:
            super().sendall(packet)
            logger.info(
                "TCP send: %d bytes. And 'll sleep for %d seconds. ",
                len(packet),
                self.send_interval,
            )
            logger.debug(
                "TCP send: %s",
                packet,
            )
            time.sleep(self.send_interval)

        logger.info("----------finish------------ %s", sni)

    def send(self, data):
        self.sendall(data=data)
        return len(data)
