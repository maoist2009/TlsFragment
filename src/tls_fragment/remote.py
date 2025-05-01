"""
site
"""

from .log import logger
from .config import (
    domain_policies,
    config,
    default_policy,
    ipv4_map,
    ipv6_map,
)
from . import fragment
from . import dns_extension
import dns.resolver
from . import utils
import socket
import copy
import time
import threading

logger = logger.getChild("remote")

resolver = dns.resolver.Resolver(configure=False)
resolver.cache = dns.resolver.LRUCache()
resolver.nameservers = [
    dns_extension.ProxiedDohServer(
        f'http://127.0.0.1:{config["port"]}', url=config["doh_server"]
    )
]
resolver.timeout = 10
resolver.lifetime = 10
TTL_cache = {}  # TTL for each IP
lock_TTL_cache = threading.Lock()


def redirect(ip):
    ans = ""
    if ip.find(":") != -1:
        ans = ipv4_map.search(utils.ip_to_binary_prefix(ip))
        if ans is None:
            return ip
        else:
            logger.info("IPredirect %s to %s", ip, ans)
            return ans
    else:
        ans = ipv6_map.search(utils.ip_to_binary_prefix(ip))
        if ans is None:
            return ip
        else:
            logger.info("IPredirect %s to %s", ip, ans)
            return ans


class Remote:
    policy: dict
    domain: str
    address: str
    sock: socket.socket
    port: int

    def __init__(self, domain: str, port=443):
        matched_domains = domain_policies.search("^" + domain + "$")
        self.domain = domain
        if matched_domains:
            self.policy = copy.deepcopy(
                config["domains"].get(sorted(matched_domains, key=len, reverse=True)[0])
            )
        else:
            self.policy = {}
        self.policy |= default_policy
        self.policy.setdefault("port", port)

        if self.policy.get("IP") is None:
            if self.policy.get("IPtype") == "ipv6":
                try:
                    self.address = resolver.resolve(domain, "AAAA")[0].to_text()
                except dns.resolver.NoAnswer:
                    self.address = resolver.resolve(domain, "A")[0].to_text()
            else:
                try:
                    self.address = resolver.resolve(domain, "A")[0].to_text()
                except:
                    self.address = resolver.resolve(domain, "AAAA")[0].to_text()
        else:
            self.address = self.policy["IP"]
        self.address = redirect(self.address)
        self.port = self.policy["port"]

        logger.info("%s %d", self.address, self.port)
        # res["IP"]="127.0.0.1"

        if self.policy["fake_ttl"] == "query" and self.policy["mode"] == "FAKEDesync":
            logger.info(
                "FAKE TTL for %s is %s", self.address, self.policy.get("fake_ttl")
            )
            if TTL_cache.get(self.address) != None:
                self.policy["fake_ttl"] = TTL_cache[self.address] - 1
                logger.info(
                    "FAKE TTL for %s is %d", self.address, self.policy.get("fake_ttl")
                )
            else:
                logger.info("%s %d", self.address, self.policy.get("port"))
                val = utils.get_ttl(self.address, self.policy.get("port"))
                if val == -1:
                    raise Exception("ERROR get ttl")
                TTL_cache[self.address] = val
                self.policy["fake_ttl"] = val - 1
                logger.info(
                    "FAKE TTL for %s is %d", self.address, self.policy.get("fake_ttl")
                )

        logger.info("%s --> %s", domain, self.policy)
        if ":" in self.address:
            self.sock = socket.socket(
                socket.AF_INET6,
                socket.SOCK_STREAM,
            )
        else:
            self.sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(config["my_socket_timeout"])

    def connect(self):
        self.sock.connect((self.address, self.port))

    def send(self, data):
        self.sock.sendall(data)

    def recv(self, size):
        return self.sock.recv(size)

    def send_fraggmed_tls_data(self, data):
        """send fragged tls data"""
        try:
            sni = utils.extract_sni(data)
        except ValueError:
            self.send(data)
            return
        logger.info("To send: %d Bytes.", len(data))
        if sni is None:
            self.send(data)
            return

        logger.debug("sending:    %s", data)
        base_header = data[:3]
        record = data[5:]

        fragmented_tls_data = fragment.fragment_pattern(
            record, sni, self.policy["num_tls_pieces"]
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

        fragmented_tcp_data = fragment.fragment_pattern(
            tcp_data,
            tcp_data[
                len(fragmented_tls_data[0]) : len(tcp_data)
                - len(fragmented_tls_data[-1])
                + 1
            ],
            self.policy["num_tcp_pieces"],
        )

        for packet in fragmented_tcp_data:
            self.send(packet)
            logger.info(
                "TCP send: %d bytes. And 'll sleep for %d seconds. ",
                len(packet),
                self.policy["send_interval"],
            )
            logger.debug(
                "TCP send: %s",
                packet,
            )
            time.sleep(self.policy["send_interval"])

        logger.info("----------finish------------ %s", sni)
