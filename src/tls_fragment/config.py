from pathlib import Path
import shutil
import ahocorasick
import json
import ipaddress
import random
import time

def expand_pattern(s):
    left_index, right_index = s.find('('), s.find(')')
    if left_index == -1 and right_index == -1:
        return s.split('|')
    if -1 in (left_index, right_index):
        raise ValueError("Both '(' and ')' must be present", s)
    if left_index > right_index:
        raise ValueError("'(' must occur before ')'", s)
    if right_index == left_index + 1:
        raise ValueError(
            'A vaild string should exist between a pair of parentheses', s
        )
    prefix = s[:left_index]
    suffix = s[right_index + 1:]
    inner = s[left_index + 1:right_index]
    return [prefix + part + suffix for part in inner.split('|')]


def ip_to_binary_prefix(ip_or_network:str):
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
            raise ValueError(f"input {ip_or_network} is not a valid IP or network address")


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

if not Path("config.json").exists():
    shutil.copyfile(basepath / "config.json", "config.json")
with open("config.json", "rb") as f:
    _config = json.load(f)


config = {**_config, **config}

try:
    with open("config_extra.json", "rb") as f:
        extra_config = json.load(f)
    config={**config, **extra_config} 
except:
    pass

default_policy = config["default_policy"]
default_policy["fake_packet"]= default_policy["fake_packet"].encode(encoding="UTF-8")

expanded_policies = {}
for key in config['domains'].keys():
    for item in key.replace(' ', '').split(','):
        for pattern in expand_pattern(item):
            expanded_policies[pattern] = config['domains'][key]

config['domains'] = expanded_policies

domain_map = ahocorasick.AhoCorasick(*config["domains"].keys())
ipv4_map = Trie()
ipv6_map = Trie()

expanded_policies = {}
for key in config['IPs'].keys():
    for item in key.replace(' ', '').split(','):
        for pattern in expand_pattern(item):
            expanded_policies[pattern] = config['IPs'][key]

config['IPs'] = expanded_policies

for k, v in config["IPs"].items():
    if ':' in k:
        ipv6_map.insert(ip_to_binary_prefix(k), v)
    else:
        ipv4_map.insert(ip_to_binary_prefix(k), v)

if default_policy["fake_ttl"] == "auto":
    # temp code for auto fake_ttl
    default_policy["fake_ttl"] = random.randint(10, 60)

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
