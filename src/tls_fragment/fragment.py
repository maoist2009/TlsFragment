"""
tls data fragment.
"""

import random
from .log import logger
from . import remote
import time


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

def send_fraggmed_tls_data(sock: remote.Remote, data):
    """send fragged tls data"""
    sni=sock.policy.get("sni")

    logger.info("To send: %d Bytes.", len(data))
    if sni is None:
        sock.send(data)
        return

    logger.debug("sending:    %s", data)
    base_header = data[:3]
    record = data[5:]

    fragmented_tls_data = fragment_pattern(
        record, sni, sock.policy["num_tls_pieces"]
    )
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
        sock.policy["num_tcp_pieces"],
    )

    for packet in fragmented_tcp_data:
        sock.send(packet)
        logger.info(
            "TCP send: %d bytes. And 'll sleep for %d seconds. ",
            len(packet),
            sock.policy["send_interval"],
        )
        logger.debug(
            "TCP send: %s",
            packet,
        )

        time.sleep(sock.policy["send_interval"])

    logger.info("----------finish------------ %s", sni)