import requests
import dns.message
import dns.rdatatype
import dns.query
import base64
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

            for rrset in answer_msg.answer:
                if (dns_type == "A" and rrset.rdtype == dns.rdatatype.A) or \
                   (dns_type == "AAAA" and rrset.rdtype == dns.rdatatype.AAAA):
                    ip = rrset[0].address
                    logger.info(f"Resolved {server_name} to {ip}")
                    return ip

            logger.warning(f"No {dns_type} record for {server_name}")
            return None

        except Exception as e:
            logger.error(f"DNS query error: {repr(e)}")
            raise Exception("DNS query failed")