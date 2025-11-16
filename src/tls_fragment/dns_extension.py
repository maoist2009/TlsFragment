import requests
import dns.message
import dns.rdatatype
import dns.query
import base64
import time
from urllib.parse import urlparse

from .log import logger
logger = logger.getChild('dns_extension')


class MyDoh:
    def __init__(self, proxy, url):
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            self.mode = 'doh'
            self.url = url  # as-is
            self.req = requests.Session()
            # EXACTLY as original: {'https': proxy}
            self.knocker_proxy = {'https': proxy}
        elif parsed.scheme == 'udp':
            self.mode = 'udp'
            self.udp_host = parsed.hostname
            self.udp_port = parsed.port or 53
            self.req = None
            self.knocker_proxy = None
        else:
            raise ValueError(f"Unsupported scheme: {parsed.scheme}")

    def resolve(self, server_name, dns_type):
        logger.info(f"Online DNS Query {server_name} via {self.mode.upper()}")
        try:
            query_message = dns.message.make_query(server_name, dns_type)

            if self.mode == 'doh':
                query_wire = query_message.to_wire()
                query_base64 = base64.urlsafe_b64encode(query_wire).decode().rstrip('=')
                query_url = self.url + query_base64

                ans = self.req.get(
                    query_url,
                    params={'type': dns_type, 'ct': 'application/dns-message'},
                    headers={'accept': 'application/dns-message'},
                    proxies=self.knocker_proxy  # <-- {'https': proxy}, as original
                )

                if ans.status_code == 200 and ans.headers.get('content-type') == 'application/dns-message':
                    answer_msg = dns.message.from_wire(ans.content)
                else:
                    logger.error(f"DoH error: {ans.status_code} {ans.reason}")
                    raise Exception("DoH query failed")

            else:  # udp
                answer_msg = dns.query.udp(query_message, self.udp_host, port=self.udp_port, timeout=5)

            result,current_time = {},time.time() 
    
            for rrset in answer_msg.answer:
                domain = rrset.name.to_text()
                if domain[-1]=='.':
                    domain=domain[:-1]
                ttl = rrset.ttl
                expires = current_time + ttl
                
                if rrset.rdtype == dns.rdatatype.CNAME:
                    target = rrset[0].target.to_text()
                    if target[-1]=='.':
                        target=target[:-1]
                elif rrset.rdtype == dns.rdatatype.A:
                    target = [record.address for record in rrset]
                elif rrset.rdtype == dns.rdatatype.AAAA:
                    target = [record.address for record in rrset]

                result[domain] = {
                    "route": target,
                    "expires": expires
                }

            # print(answer_msg,result)
            logger.info(f"DNS query result: {result}")
            
            return result
        except Exception as e:
            logger.error(f"DNS query error: {repr(e)}")
            raise Exception("DNS query failed")