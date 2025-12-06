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
    data_length = len(data)
    fragmented_content = []
    if len(data) > 1:
        dividing_points = random.sample(
            range(1, data_length), min(num, data_length - 1)
        )
    else:
        fragmented_content.append(data)
        return
    dividing_points.append(0)
    dividing_points.append(data_length)
    dividing_points.sort()
    for i in range(len(dividing_points) - 1):
        fragmented_content.append(data[dividing_points[i]:dividing_points[i + 1]])
    return fragmented_content


def fragment_pattern(data, pattern, len_sni: int, num_pieces: int):
    """
    fragment pattern into at least num parts.
    the first part of the pattern contains in
    fragmented_data[0]
    """
    fragmented_data = []
    position = data.find(pattern)
    logger.debug(f"{pattern} {position}")
    if position == -1:
        return fragment_content(data, 2 * num_pieces)

    # print(position)
    pattern_length = len(pattern)
    data_length = len(data)

    fragmented_data.extend(fragment_content(data[0:position], num_pieces))

    l = len(fragmented_data)

    if len_sni >= len(pattern) / 2:
        len_sni = int(len(pattern) / 2)
        logger.info("len_sni was too big so it has been set to %d", len_sni)

    num = int(pattern_length / len_sni)

    if num * len_sni < pattern_length:
        num += 1

    for i in range(num):
        fragmented_data.append(
            data[position + i * len_sni:position + (i + 1) * len_sni]
        )

    r = len(fragmented_data)

    fragmented_data.extend(
        fragment_content(data[position + num * len_sni:], num_pieces)
    )
    return fragmented_data, l, r

def send_fraggmed_tls_data(sock: remote.Remote, data):
    """send fragged tls data"""
    sni = sock.sni

    logger.info("To send: %d Bytes.", len(data))
    if sni is None:
        sock.send(data)
        return

    logger.debug(f"Sending:    {data}")
    base_header = data[:3]
    record = data[5:]

    fragmented_tls_data, l, r = fragment_pattern(
        record, sni, sock.policy["len_tls_sni"], sock.policy["num_tls_pieces"]
    )
    tcp_data = b""
    for i, _ in enumerate(fragmented_tls_data):
        tmp = fragmented_tls_data[i] = (
            base_header
            + int.to_bytes(len(fragmented_tls_data[i]), byteorder="big", length=2)
            + fragmented_tls_data[i]
        )
        tcp_data += tmp
        logger.debug("Adding frag: %d bytes.", len(tmp))
        logger.debug(f"Adding frag: {tmp}")

    logger.info("TLS fraged: %d Bytes.", len(tcp_data))
    logger.debug(f"TLS fraged: {tcp_data}")

    lenl = 0
    for i in range(0,l):
        lenl += len(fragmented_tls_data[i])
    lenr = lenl
    for i in range(l, r):
        lenr += len(fragmented_tls_data[i])

    fragmented_tcp_data, l, r = fragment_pattern(
        tcp_data,
        tcp_data[lenl:lenr],
        sock.policy["len_tcp_sni"],
        sock.policy["num_tcp_pieces"],
    )
    
    obboffset=sock.policy.get("oob_offset")

    for i in range(0,len(fragmented_tcp_data)):
        packet=fragmented_tcp_data[i]
        if sock.policy.get("oob_str") and i==l+obboffset:
                sock.send_with_oob(packet,bytes(sock.policy["oob_str"][0],encoding="utf-8"))
        else:
            sock.send(packet)
        logger.debug(
            "TCP send: %d bytes. And 'll sleep for %d seconds.",
            len(packet),
            sock.policy["send_interval"],
        )
        logger.debug(f"TCP send: {packet}")

        time.sleep(sock.policy["send_interval"])

    logger.info(f"----------finish------------ {sni}")
