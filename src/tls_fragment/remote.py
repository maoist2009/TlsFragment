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

from .dns_extension import MyDoh
import socket
import copy
import threading
from . import utils
from .l38 import merge_dict
import ipaddress

logger = logger.getChild("remote")

resolver = MyDoh(proxy=f'http://127.0.0.1:{config["DOH_port"]}', url=config["doh_server"])

from .config import DNS_cache, TTL_cache, write_DNS_cache, write_TTL_cache
cnt_upd_TTL_cache = 0
lock_TTL_cache = threading.Lock()
cnt_upd_DNS_cache = 0
lock_DNS_cache = threading.Lock()


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

def match_domain(domain):
    matched_domains = domain_policies.search("^" + domain + "$")
    if matched_domains:
        return copy.deepcopy(
                config["domains"].get(sorted(matched_domains, key=len, reverse=True)[0])
            )
    else:
        return {}


class Remote:
    policy: dict
    domain: str
    address: str
    sock: socket.socket
    port: int
    protocl: int
    # 6 tcp 17 udp

    def __init__(self, domain: str, port=443, protocol=6):
        self.domain = domain
        self.policy = match_domain(domain)
        self.policy = merge_dict(self.policy, default_policy)
        self.policy.setdefault("port", port)
        self.protocol=protocol
        
        try:
            ipaddress.IPv4Address(self.domain)
            self.policy["IP"]=self.domain
        except:
            try:
                ipaddress.IPv6Address(self.domain)
                self.policy["IP"]=self.domain
            except:
                pass
        
        if self.policy.get("IP") is None:
            if DNS_cache.get(self.domain) != None:
                self.address = DNS_cache[self.domain]
                logger.info("DNS cache for %s is %s", self.domain, self.address)
            else:
                if self.policy.get("IPtype") == "ipv6":
                    try:
                        self.address = resolver.resolve(self.domain, "AAAA")
                    except:
                        self.address = resolver.resolve(self.domain, "A")
                else:
                    try:
                        self.address = resolver.resolve(self.domain, "A")
                    except:
                        self.address = resolver.resolve(self.domain, "AAAA")
                if self.address:
                    global cnt_upd_DNS_cache, lock_DNS_cache
                    lock_DNS_cache.acquire()
                    DNS_cache[self.domain] = self.address
                    cnt_upd_DNS_cache += 1
                    if cnt_upd_DNS_cache >= config["TTL_cache_update_interval"]:
                        cnt_upd_DNS_cache = 0
                        write_DNS_cache()
                    lock_DNS_cache.release()
                    logger.info("DNS cache for %s to %s", self.domain, self.address)
        else:
            self.address = self.policy["IP"]
        self.address = redirect(self.address)
        self.port = self.policy["port"]

        logger.info("%s %d", self.address, self.port)
        # res["IP"]="127.0.0.1"

        if self.policy["fake_ttl"] == "query" and self.policy["mode"] == "FAKEdesync":
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
                global cnt_upd_TTL_cache, lock_TTL_cache
                lock_TTL_cache.acquire()
                TTL_cache[self.address] = val
                cnt_upd_TTL_cache += 1
                if cnt_upd_TTL_cache >= config["TTL_cache_update_interval"]:
                    cnt_upd_TTL_cache = 0
                    write_TTL_cache()
                lock_TTL_cache.release()
                self.policy["fake_ttl"] = val - 1
                logger.info(
                    "FAKE TTL for %s is %d", self.address, self.policy.get("fake_ttl")
                )

        logger.info("%s --> %s", domain, self.policy)
        
        
        if ":" in self.address:
            iptype=socket.AF_INET6
        else:
            iptype=socket.AF_INET
            
        if self.protocol==6:
            socktype=socket.SOCK_STREAM
        elif self.protocol==17:
            socktype=socket.SOCK_DGRAM
        else:
            raise ValueError("Unknown sock type",self.protocol)
            
        self.sock = socket.socket(iptype,socktype)
        
        if self.protocol==6:    
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(config["my_socket_timeout"])

    def connect(self):
        if self.protocol==6:
            self.sock.connect((self.address, self.port))
        elif self.protocol==17:
            pass

    def send(self, data):
        if self.protocol==6:
            self.sock.sendall(data)
        elif self.protocol==17:
            self.sock.send_to(data,(self.address,self.port))

    def recv(self, size):
        if self.protocol==6:
            return self.sock.recv(size)
        elif self.protocol==17:
            while True:
                data, address = self.sock.recvfrom(size)
                if address == (self.address,self.port):
                    return data

 
    def close(self):
        if self.protocol==6:
            self.sock.close()
        elif self.protocol==17:
            pass
