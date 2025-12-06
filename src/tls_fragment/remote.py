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
    write_TTL_cache,
    ip_to_binary_prefix
)

from .dns_extension import MyDoh
import socket
import threading
import time
import copy
from . import utils

logger = logger.getChild("remote")

resolver = MyDoh(
    proxy=f"http://127.0.0.1:{config['DOH_port']}", url=config["doh_server"]
)
cnt_upd_TTL_cache = 0
lock_TTL_cache = threading.Lock()

t = time.time()
temp_DNS_cache = DNS_cache.copy()
for domain, value in temp_DNS_cache.items():
    if value["expires"] is not None and value["expires"] < t:
        logger.info(f"DNS cache for {domain} expired and will be removed.")
        DNS_cache.pop(domain)
temp_DNS_cache.clear()

write_DNS_cache()

cnt_upd_DNS_cache = 0
lock_DNS_cache = threading.Lock()


def match_ip(ip:str):
    if ":" in ip:
        return copy.deepcopy(ipv6_map.search(utils.ip_to_binary_prefix(ip)))
    else:
        return copy.deepcopy(ipv4_map.search(utils.ip_to_binary_prefix(ip)))


def match_domain(domain:str):
    matched_domains = domain_map.search("^" + domain + "$")
    if matched_domains:
        return copy.deepcopy(
            config["domains"].get(sorted(matched_domains, key=len, reverse=True)[0])
        )
    else:
        return {}
    
def get_policy(address:str) -> dict:
    if utils.is_ip_address(address):
        return match_ip(address)
    else:
        return match_domain(address)
    

    
def route(address:str,policy:dict,tmp_DNS_cache:dict={}) -> {str,dict}:
    policy = {**policy, **get_policy(address)}
    # print(policy)
    """
    理清逻辑
    rawaddress是当前地址，address是用来计算的，preaddress表示有没有^，policy["route"]是目前的重定向配置（^只会）
    addresss是不会带^的
    如果是域名要进行dns查询，就进行查询到cname，继承^，使其最终不重定向，递归
    如果不是，此时^意味着仍需要计算
    """
    # print(address,policy)
    redirectm = policy.get("route")
    if redirectm[0] == "^":
        stopchain = True
        redirectm = redirectm[1:]
    else:
        stopchain = False
    if not utils.is_ip_address(address) and redirectm == address:
        policy["route"]=default_policy["route"]
        return route(address,policy,tmp_DNS_cache)
        
    if not utils.is_ip_address(address) and redirectm[1:]==".dns.resolve":
        """
        示例dns返回
        {
            'cn.bing.com': {
                'route': 'cn-bing-com.cn.a-0001.a-msedge.net', 'expires': 1763277777.35967
            },
            'cn-bing-com.cn.a-0001.a-msedge.net': {
                'route': 'a-0001.a-msedge.net', 'expires': 1763274776.35967
            },
            'a-0001.a-msedge.net': {
                'route': ['204.79.197.200', '13.107.21.200'], 'expires': 1763274237.35967
            }
        }
        """
        if DNS_cache.get(address) is not None:
            ansaddress = DNS_cache[address]["route"]
            logger.info("DNS cache for %s is %s", address, ansaddress)
        elif tmp_DNS_cache.get(address) is not None:
            ansaddress = tmp_DNS_cache[address]["route"]
            logger.debug("CNAME DNS cache for %s is %s", address, ansaddress)
        else:
            if redirectm == "6.dns.resolve":
                try:
                    tmp_DNS_cache= {**tmp_DNS_cache,**resolver.resolve(address, "AAAA")}
                    ansaddress = tmp_DNS_cache[address]["route"]
                except:
                    tmp_DNS_cache= {**tmp_DNS_cache,**resolver.resolve(address, "A")}
                    ansaddress = tmp_DNS_cache[address]["route"]
            else:
                try:
                    tmp_DNS_cache= {**tmp_DNS_cache,**resolver.resolve(address, "A")}
                    ansaddress = tmp_DNS_cache[address]["route"]
                except:
                    import traceback
                    traceback.print_exc()
                    tmp_DNS_cache= {**tmp_DNS_cache,**resolver.resolve(address, "AAAA")}
                    ansaddress = tmp_DNS_cache[address]["route"]

            if ansaddress and policy["DNS_cache"]:
                global cnt_upd_DNS_cache, lock_DNS_cache
                lock_DNS_cache.acquire()
                if ttl := policy.get("DNS_cache_TTL"):
                    tmp_DNS_cache[address]["expires"] = time.time() + ttl
                DNS_cache[address] = tmp_DNS_cache[address]
                cnt_upd_DNS_cache += 1
                print(cnt_upd_DNS_cache)
                if cnt_upd_DNS_cache >= config["DNS_cache_update_interval"]:
                    cnt_upd_DNS_cache = 0
                    write_DNS_cache()
                lock_DNS_cache.release()
                logger.info(f"DNS cache {address} as {tmp_DNS_cache[address]}")

        if type(ansaddress)==list:
            # 是list必然是ip
            # 我们暂时取第一个，之后可能加入优选
            ansaddress=ansaddress[0]
    else:
        if utils.is_ip_address(address):
            if redirectm[1:] == ".dns.resolve":
                return address,policy
        try:
            ip_to_binary_prefix(redirectm)
            ansaddress = utils.calc_redirect_ip(address, redirectm)
        except:
            ansaddress = redirectm
        if stopchain:
            return ansaddress,policy

    if ansaddress == address:
        return address,policy
    logger.info(f"route {address} to {ansaddress}")
    return route(ansaddress,policy,tmp_DNS_cache)


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
        self.protocol = protocol
        
        self.policy = copy.deepcopy(default_policy)
        self.policy.setdefault("port", port)
        self.address, self.policy = route(self.domain, self.policy)
        # print(self.policy)

        self.port = self.policy["port"]

        logger.info("connect %s %d", self.address, self.port)

        if self.policy["fake_ttl"][0] == "q" and self.policy["mode"] == "FAKEdesync":
            logger.info(f"FAKE TTL for {self.address} is {self.policy.get('fake_ttl')}")
            if TTL_cache.get(self.address) != None:
                val = TTL_cache[self.address]
                logger.info("dist for %s is %d, found in cache", self.address, val)
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
                logger.info("dist for %s is %d", self.address, val)
            self.policy["fake_ttl"] = utils.fake_ttl_mapping(
                self.policy["fake_ttl"], val
            )
            logger.info("FAKE TTL for %s is %d", self.address, self.policy["fake_ttl"])

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
          
    def send_with_oob(self, data, oob):
        if self.protocol == 17:
            self.sock.sendall(data)
        elif self.protocol == 6:
            print("OOB ",data,oob)
            self.sock.send(data+oob,socket.MSG_OOB)
            # self.sock.sendall(data)

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
                        try:
                            ans = utils.build_socks5_udp_ans(
                                address, port, utils.fake_udp_dns_query(data)
                            )
                            logger.debug(ans)
                            self.client_sock.sendall(ans)
                            logger.info("UDP dns dealt")
                            return
                        except Exception as e:
                            logger.warning("Error making up dns answer: " + repr(e))
                except:
                    pass
            self.sock.sendto(data, (address, port))

    def recv(self, size):
        if self.protocol == 6:
            return self.sock.recv(size)
        elif self.protocol == 17:
            data, address = self.sock.recvfrom(size)
            logger.info(f"receive from {address[0]}:{address[1]}")
            ans = utils.build_socks5_udp_ans(address[0], int(address[1]), data)
            logger.debug(ans)
            return ans

    def close(self):
        if self.protocol == 6:
            self.sock.close()
        elif self.protocol == 17:
            pass
