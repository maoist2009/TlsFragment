from pathlib import Path
import shutil
import ahocorasick
import json
from tls_fragment.utils import ip_to_binary_prefix
import random

basepath = Path(__file__).parent.parent

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

config |= _config
default_policy = {
    "num_tls_pieces": config["num_tls_pieces"],
    "num_tcp_pieces": config["num_tcp_pieces"],
    "mode": config["mode"],
    "fake_packet": config["fake_packet"].encode(encoding="UTF-8"),
    "fake_ttl": config["fake_ttl"],
    "fake_sleep": config["fake_sleep"],
    "port": 443,
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
