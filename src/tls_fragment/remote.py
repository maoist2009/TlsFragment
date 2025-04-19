"""
site
"""

from tls_fragment.log import logger
from tls_fragment.config import (
    domain_policies,
    config,
    default_policy,
    ipv4_map,
    ipv6_map,
)
from tls_fragment import fragment
from tls_fragment import dns_extension
import dns.resolver
from tls_fragment.utils import ip_to_binary_prefix, get_ttl
import socket
import copy
import threading

resolver = dns.resolver.Resolver()
resolver.cache = dns.resolver.LRUCache()
resolver.nameservers = [
    dns_extension.ProxiedDohServer(
        f'http://127.0.0.1:{config["port"]}', url=config["doh_server"]
    )
]
TTL_cache = {}  # TTL for each IP
lock_TTL_cache = threading.Lock()


def redirect(ip):
    ans = ""
    if ip.find(":") != -1:
        ans = ipv4_map.search(ip_to_binary_prefix(ip))
        if ans is None:
            return ip
        else:
            logger.info("IPredirect %s to %s", ip, ans)
            return ans
    else:
        ans = ipv6_map.search(ip_to_binary_prefix(ip))
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
        if len(matched_domains):
            self.policy = copy.deepcopy(
                config["domains"].get(
                    sorted(matched_domains, key=lambda x: len(x), reverse=True)[0]
                )
            )
        self.policy |= default_policy

        if self.policy.get("IP") is None:
            if config["enalbe_ipv6"]:
                try:
                    self.address = resolver.resolve(domain, "AAAA")
                except dns.asyncresolver.NoAnswer:
                    self.address = resolver.resolve(domain, "A")
            else:
                self.address = resolver.resolve(domain, "A")
        else:
            self.address = self.policy["IP"]
        self.address = redirect(self.address)
        self.port = port
        # res["IP"]="127.0.0.1"

        if self.policy["fake_ttl"] == "query":
            logger.info(
                "FAKE TTL for %s is %s", self.address, self.policy.get("fake_ttl")
            )
            if TTL_cache.get(self.address) != None:
                self.policy["fake_ttl"] = TTL_cache[self.address] - 1
                logger.info(
                    "FAKE TTL for %s is %d", self.address, self.policy.get("fake_ttl")
                )
            else:
                logger.info(self.address, self.policy.get("port"))
                val = get_ttl(self.address, self.policy.get("port"))
                if val == -1:
                    raise Exception("ERROR get ttl")
                TTL_cache[self.address] = val
                self.policy["fake_ttl"] = val - 1
                logger.info(
                    "FAKE TTL for %s is %d", self.address, self.policy.get("fake_ttl")
                )

        logger.info("%s --> %s", domain, self.policy)
        if ":" in self.address:
            self.sock = fragment.FragSock(
                socket.AF_INET6,
                socket.SOCK_STREAM,
                num_of_pieccs_tls=self.policy["num_tls_pieces"],
                num_of_pieccs_tcp=self.policy["num_tcp_pieces"],
                send_interval=config["tcp_sleep"],
            )
        else:
            self.sock = fragment.FragSock(
                socket.AF_INET,
                socket.SOCK_STREAM,
                num_of_pieccs_tls=self.policy["num_tls_pieces"],
                num_of_pieccs_tcp=self.policy["num_tcp_pieces"],
                send_interval=config["tcp_sleep"],
            )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(config["my_socket_timeout"])

    def connect(self):
        self.sock.connect((self.address, self.port))

    def send(self, data):
        self.sock.sendall(data)

    def recv(self, size):
        return self.sock.recv(size)
