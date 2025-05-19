from pathlib import Path
import shutil
import ahocorasick
import json
import ipaddress
import random
from .l38 import merge_dict   

basepath = Path(__file__).parent.parent.parent

config = {}


def ip_to_binary_prefix(ip_or_network):
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
            raise ValueError(f"输入 {ip_or_network} 不是有效的 IP 地址或网络")


class TrieNode:
    def __init__(self):
        self.children = [None, None]
        self.val = None


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, prefix, value):
        node = self.root
        for bit in prefix:
            index = int(bit)
            if not node.children[index]:
                node.children[index] = TrieNode()
            node = node.children[index]
        node.val = value

    def search(self, prefix):
        node = self.root
        ans = None
        for bit in prefix:
            index = int(bit)
            if node.val != None:
                ans = node.val
            if not node.children[index]:
                return ans
            node = node.children[index]
        if node.val != None:
            ans = node.val
        return ans


ipv4trie = Trie()
ipv6trie = Trie()

if not Path("config.json").exists():
    shutil.copyfile(basepath / "config.json", "config.json")
with open("config.json", "rb") as f:
    _config = json.load(f)

config = merge_dict(config, _config)
default_policy = {
    "num_tls_pieces": config["num_tls_pieces"],
    "num_tcp_pieces": config["num_tcp_pieces"],
    "len_tcp_sni": config["len_tcp_sni"],
    "len_tls_sni": config["len_tls_sni"],
    "mode": config["mode"],
    "fake_packet": config["fake_packet"].encode(encoding="UTF-8"),
    "fake_ttl": config["fake_ttl"],
    "fake_sleep": config["fake_sleep"],
    "send_interval": config["send_interval"],
    "DNS_cache": config["DNS_cache"],
    "TTL_cache": config["TTL_cache"],
    "safety_check": config["safety_check"],
    "UDPfakeDNS": config["UDPfakeDNS"],
    "BySNIfirst": config["BySNIfirst"],
}

domain_policies = ahocorasick.AhoCorasick(*config["domains"].keys())
ipv4_map = Trie()
ipv6_map = Trie()

for key in config["IPredirect"].keys():
    if key.find(":") != -1:
        ipv6_map.insert(ip_to_binary_prefix(key), config["IPredirect"][key])
    else:
        ipv4_map.insert(ip_to_binary_prefix(key), config["IPredirect"][key])

if config["fake_ttl"] == "auto":
    # temp code for auto fake_ttl
    config["fake_ttl"] = random.randint(10, 60)

TTL_cache = {}  # TTL for each IP
DNS_cache = {}  # DNS cache for each domain

try:
    with open("DNS_cache.json", "rb") as f:
        DNS_cache = json.load(f)
except FileNotFoundError:
    pass

try:
    with open("TTL_cache.json", "rb") as f:
        TTL_cache = json.load(f)
except FileNotFoundError:
    pass

def write_DNS_cache():
    with open("DNS_cache.json", "w") as f:
        json.dump(DNS_cache, f)

def write_TTL_cache():
    with open("TTL_cache.json", "w") as f:
        json.dump(TTL_cache, f)