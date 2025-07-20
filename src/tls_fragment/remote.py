"""
site
"""

from .log import logger
from .config import (
    domain_map,
    config,
    default_policy,
    ipv4_map,
    ipv6_map,
    DNS_cache,
    TTL_cache,
    write_DNS_cache,
    write_TTL_cache
)

from .dns_extension import MyDoh
import socket
import threading
import time
from . import utils

logger = logger.getChild("remote")

resolver = MyDoh(proxy=f'http://127.0.0.1:{config["DOH_port"]}', url=config["doh_server"])
cnt_upd_TTL_cache = 0
lock_TTL_cache = threading.Lock()

t = time.time()
temp_DNS_cache = DNS_cache.copy()
for domain, value in temp_DNS_cache.items():
    if value['expires'] is not None and value['expires'] < t:
        logger.info(
            f'DNS cache for {domain} expired and will be removed.'
        )
        DNS_cache.pop(domain)
temp_DNS_cache.clear()
        
write_DNS_cache()

cnt_upd_DNS_cache = 0
lock_DNS_cache = threading.Lock()
def match_ip(ip):
    if ':' in ip:
        return ipv6_map.search(utils.ip_to_binary_prefix(ip))
    else:
        return ipv4_map.search(utils.ip_to_binary_prefix(ip))
        
def redirect_ip(ip):
    mapped_ip_policy=match_ip(ip)
    if mapped_ip_policy is None or mapped_ip_policy.get("redirect") is None:
        return ip
    mapped_ip = mapped_ip_policy["redirect"]
    
    stopchain=False
    if mapped_ip[0] == "^":
        mapped_ip=mapped_ip[1:]
        stopchain=True
    mapped_ip = utils.calc_redirect_ip(ip,mapped_ip)
    
    if ip==mapped_ip:
        return mapped_ip
    logger.info(f"IP redirect {ip} to {mapped_ip}")
    if stopchain:
        return mapped_ip
    return redirect_ip(mapped_ip)

def match_domain(domain):
    matched_domains = domain_map.search("^" + domain + "$")
    if matched_domains:
        import copy
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
        self.policy = {**default_policy, **self.policy}
        self.policy.setdefault("port", port)
        self.protocol = protocol
        
        if utils.is_ip_address(self.domain):
            self.policy["IP"] = self.domain
        
        if self.policy.get("IP") is None:
            if DNS_cache.get(self.domain) is not None:
                self.address = DNS_cache[self.domain]['ip']
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
                if self.address and self.policy["DNS_cache"]:
                    global cnt_upd_DNS_cache, lock_DNS_cache
                    lock_DNS_cache.acquire()
                    if ttl := self.policy.get('DNS_cache_TTL'):
                        expires = time.time() + ttl
                    else:
                        expires = None
                    DNS_cache[self.domain] = {
                        'ip': self.address, 'expires': expires
                    }
                    cnt_upd_DNS_cache += 1
                    if cnt_upd_DNS_cache >= config["DNS_cache_update_interval"]:
                        cnt_upd_DNS_cache = 0
                        write_DNS_cache()
                    lock_DNS_cache.release()
                    logger.info(f"DNS cache for {self.domain} to {self.address}")
            self.address = redirect_ip(self.address)
            # will redirect ip only if it it connected by domain
        else:
            self.address = self.policy["IP"]
            if config["redirect_when_ip"]:
                self.address = redirect_ip(self.address)

        mapped_ip_policy=match_ip(self.address)
        if mapped_ip_policy is not None:
                self.policy={**self.policy,**mapped_ip_policy}

        self.port = self.policy["port"]

        logger.info("connect %s %d", self.address, self.port)
        
        if self.policy["fake_ttl"][0] == "q" and self.policy["mode"] == "FAKEdesync":
            logger.info(f'FAKE TTL for {self.address} is {self.policy.get("fake_ttl")}')
            if TTL_cache.get(self.address) != None:
                val = TTL_cache[self.address]
                logger.info(
                    "dist for %s is %d, found in cache", self.address, val
                )
            else:
                val = utils.get_ttl(self.address, self.policy.get("port"))
                if val == -1:
                    raise Exception("ERROR get ttl")
                if self.policy["TTL_cache"]:
                    global cnt_upd_TTL_cache, lock_TTL_cache
                    lock_TTL_cache.acquire()
                    TTL_cache[self.address] = val
                    cnt_upd_TTL_cache += 1
                    if cnt_upd_TTL_cache >= config["TTL_cache_update_interval"]:
                        cnt_upd_TTL_cache = 0
                        write_TTL_cache()
                    lock_TTL_cache.release()
                logger.info(
                    "dist for %s is %d", self.address, val
                )
            self.policy["fake_ttl"]=utils.fake_ttl_mapping(self.policy["fake_ttl"],val) 
            logger.info(
                    "FAKE TTL for %s is %d", self.address, self.policy["fake_ttl"])

        logger.info(f"{domain} --> {self.policy}")

        iptype = socket.AF_INET6 if ":" in self.address else socket.AF_INET

        if self.protocol == 6:
            socktype = socket.SOCK_STREAM
            self.sock = socket.socket(iptype, socktype)
        elif self.protocol == 17:
            socktype = socket.SOCK_DGRAM
            self.sock = socket.socket(iptype, socktype)
        else:
            raise ValueError("Unknown sock type", self.protocol)
        
        if self.protocol == 6:    
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(config["my_socket_timeout"])

    def connect(self):
        if self.protocol == 6:
            self.sock.connect((self.address, self.port))
        elif self.protocol == 17:
            pass

    def send(self, data):
        if self.protocol == 6:
            self.sock.sendall(data)
        elif self.protocol == 17:
            data = data[3:]
            address, port, offset = utils.parse_socks5_address_from_data(data)
            data = data[offset:]
            logger.info(f"send to {address}:{port}")
            logger.debug(data)
            if config["UDPfakeDNS"]:
                try:
                    if utils.is_udp_dns_query(data):
                        logger.info("UDP dns detected")
                        try:
                            ans=utils.build_socks5_udp_ans(address,port,utils.fake_udp_dns_query(data))
                            logger.debug(ans)
                            self.client_sock.sendall(ans)
                            return
                        except Exception as e:
                            logger.warning("Error making up dns answer: "+repr(e))
                except:
                    pass
            self.sock.sendto(data,(address, port))

    def recv(self, size):
        if self.protocol == 6:
            return self.sock.recv(size)
        elif self.protocol == 17:
            data, address = self.sock.recvfrom(size)
            logger.info(f"receive from {address[0]}:{address[1]}")
            ans=utils.build_socks5_udp_ans(address[0], int(address[1]),data)
            logger.debug(ans)
            return ans

 
    def close(self):
        if self.protocol == 6:
            self.sock.close()
        elif self.protocol == 17:
            pass
