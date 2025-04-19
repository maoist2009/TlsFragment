import dns.query,dns.resolver
from tls_fragment import fragment
import httpx
import socket

dns.query.socket_factory = fragment.FragSock
res= dns.resolver.Resolver()


# 创建自定义传输层
transport = httpx.HTTPTransport(
    sock=fragment.FragSock(),  # 注意：需手动管理socket生命周期
)

# 使用自定义传输层
with httpx.Client(transport=transport) as client:
    response = client.get("https://example.com")
    print(response.text)

res.nameservers = ['tls://dot.sb']
res.resolve('baidu.com','A')