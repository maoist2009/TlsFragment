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
        quary_params = {
            # 'name': server_name,    # no need for this when using dns wire-format , cause 400 err on some server
            'type': 'A',
            'ct': 'application/dns-message',
            }
        logger.info("online DNS Query %s",server_name)        
    

        
        try:
            if dns_type=="ipv6":
                query_message = dns.message.make_query(server_name,'AAAA')
            else:
                query_message = dns.message.make_query(server_name,'A')
            query_wire = query_message.to_wire()
            query_base64 = base64.urlsafe_b64encode(query_wire).decode('utf-8')
            query_base64 = query_base64.replace('=','')    # remove base64 padding to append in url            

            query_url = self.url + query_base64


            ans = self.req.get( query_url , params=quary_params , headers={'accept': 'application/dns-message'} , proxies=self.knocker_proxy)
            
            # Parse the response as a DNS packet

            if ans.status_code == 200 and ans.headers.get('content-type') == 'application/dns-message':
                answer_msg = dns.message.from_wire(ans.content)
  
                resolved_ip = None
                for x in answer_msg.answer:
                    if ((dns_type=="AAAA" and x.rdtype == dns.rdatatype.AAAA) or (dns_type=="A" and x.rdtype == dns.rdatatype.A)):
                        resolved_ip = x[0].address    # pick first ip in DNS answer
                        break
                
                logger.info("online DNS --> Resolved %s to %s",server_name,resolved_ip)                
                return resolved_ip
            else:
                logger.error("online DNS --> Error DNS query: %s %s",ans.status_code,ans.reason)
        except Exception as e:
            logger.error("online DNS --> Error DNS query: %s",repr(e))
        raise Exception("online DNS --> Error DNS query")

