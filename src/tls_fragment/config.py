from pathlib import Path
import shutil
import ahocorasick
import json
import ipaddress
import random
from .utils import ip_to_binary_prefix

basepath = Path(__file__).parent.parent.parent

config = {}


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
            if node.val is not None:
                ans = node.val
            if not node.children[index]:
                return ans
            node = node.children[index]
        if node.val is not None:
            ans = node.val
        return ans


ipv4trie = Trie()
ipv6trie = Trie()

if not Path("config.json").exists():
    shutil.copyfile(basepath / "config.json", "config.json")
with open("config.json", "rb") as f:
    _config = json.load(f)

config = {**_config, **config}
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
}

domain_policies = ahocorasick.AhoCorasick(*config["domains"].keys())
ipv4_map = Trie()
ipv6_map = Trie()

for k, v in config["IPredirect"].items():
    if ':' in k:
        ipv6_map.insert(ip_to_binary_prefix(k), v)
    else:
        ipv4_map.insert(ip_to_binary_prefix(k), v)

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
