import requests
import dns.message   
import dns.rdatatype
import base64

from .log import logger
logger = logger.getChild('dns_extension')


class MyDoh:
    def __init__(self,proxy,url):
        self.url = url
        self.req = requests.session()              
        self.knocker_proxy = {
        'https': proxy
        }
        


    def resolve(self,server_name,dns_type):   
        query_params = {
            # 'name': server_name,    # no need for this when using dns wire-format , cause 400 err on some server
            'type': dns_type,
            'ct': 'application/dns-message',
            }

        logger.info(f"online DNS Query {server_name}")       
        try:
            query_message = dns.message.make_query(server_name,dns_type)
            query_wire = query_message.to_wire()
            query_base64 = base64.urlsafe_b64encode(query_wire).decode('utf-8')
            query_base64 = query_base64.replace('=','')    # remove base64 padding to append in url            

            query_url = self.url + query_base64

            # print(query_url,query_params)

            ans = self.req.get( query_url , params=query_params , headers={'accept': 'application/dns-message'} , proxies=self.knocker_proxy)
            # print(ans)
            
            # Parse the response as a DNS packet

            if ans.status_code == 200 and ans.headers.get('content-type') == 'application/dns-message':
                answer_msg = dns.message.from_wire(ans.content)
  
                resolved_ip = None
                for x in answer_msg.answer:
                    if (dns_type=="AAAA" and x.rdtype == dns.rdatatype.AAAA) or (dns_type=="A" and x.rdtype == dns.rdatatype.A):
                        resolved_ip = x[0].address    # pick first ip in DNS answer
                        break

                logger.info(f"online DNS --> Resolved {server_name} to {resolved_ip}")
                return resolved_ip
            logger.error(f"online DNS --> Error DNS query: {ans.status_code} {ans.reason}")
        except Exception as e:
            logger.error(f"online DNS --> Error DNS query: {repr(e)}")
        raise Exception("online DNS --> Error DNS query")

