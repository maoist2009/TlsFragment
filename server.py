from pathlib import Path
import socket
import requests
import threading
import time
import random
import copy
import json
import sys
import ahocorasick
import dns.message   #  --> pip install dnspython
import dns.rdatatype
import base64
import ipaddress


listen_PORT = 2500    # pyprox listening to 127.0.0.1:listen_PORT
DOH_PORT = 2500

log_every_N_sec = 30   # every 30 second , update log file with latest DNS-cache statistics

allow_insecure = True   # set true to allow certificate domain mismatch in DoH
my_socket_timeout = 120 # default for google is ~21 sec , recommend 60 sec unless you have low ram and need close soon
FAKE_ttl_auto_timeout = 1
first_time_sleep = 0.1 # speed control , avoid server crash if huge number of users flooding
accept_time_sleep = 0.01 # avoid server crash on flooding request -> max 100 sockets per second
output_data=True
datapath=Path()

domain_settings={
    "null": {
        "IP": "127.0.0.1",
        "TCP_frag": 114514,
        "TCP_sleep": 0.001,
        "TLS_frag": 114514,
        "num_TCP_fragment": 37,
        "num_TLS_fragment": 37,
    }
}

method="TLSfrag"
IPtype="ipv4"
num_TCP_fragment = 37
num_TLS_fragment = 37
TCP_sleep = 0.001
TCP_frag=0
TLS_frag=0
IPtype="ipv4"
doh_server="https://127.0.0.1/dns-query"
DNS_log_every=1
TTL_log_every=1
FAKE_packet=b""
FAKE_ttl=10
FAKE_sleep=0.01


domain_settings=None
domain_settings_tree=None


DNS_cache = {}      # resolved domains
TTL_cache = {}      # TTL for each IP
IP_DL_traffic = {}  # download usage for each ip
IP_UL_traffic = {}  # upload usage for each ip

cnt_dns_chg = 0
cnt_ttl_chg = 0
lock_DNS_cache = threading.Lock()
lock_TTL_cache = threading.Lock()
pac_domains = []
pacfile="function genshin(){}"

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
            if node.val!=None:
                ans=node.val
            if not node.children[index]:
                return ans
            node = node.children[index]
        if node.val!=None:
                ans=node.val
        return ans

ipv4trie=Trie()
ipv6trie=Trie()

def set_ttl(sock,ttl):
    if sock.family==socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

def tryipredirect(ip):
    ans=""
    if ip.find(":")!=-1:
        ans=ipv6trie.search(ip_to_binary_prefix(ip))
        if ans==None:
            return ip
        else:
            return ans
    else:
        ans=ipv4trie.search(ip_to_binary_prefix(ip))
        if ans==None:
            return ip
        else:
            return ans

def IPredirect(ip):
    while True:
        ans=tryipredirect(ip)
        if ans==ip:
            break
        elif ans[0]=="^":
            print(f"IPredirect {ip} to {ans[1:]}")
            ip=ans[1:]
            break
        else:
            print(f"IPredirect {ip} to {ans}")
            ip=ans

    return ip

def check_ttl(ip,port,ttl):
    # print(ip,port,ttl)
    try:
        if ip.find(":")!=-1:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_ttl(sock,ttl)
        sock.settimeout(FAKE_ttl_auto_timeout)
        # print(f"check_ttl {ip} {port} {ttl}")
        sock.connect((ip, port))
        sock.send(b"0")
        sock.close()
        return True
    except Exception as e:
        print(e)
        # import traceback
        # traceback.print_exc()
        return False
    finally:
        sock.close()
    
def get_ttl(ip,port):
    l=1
    r=128
    ans=-1
    while l<=r:
        mid=(l+r)//2
        val=check_ttl(ip,port,mid)
        print(l,r,mid,ans,val)
        if val:
            ans=mid
            r=mid-1
        else:
            l=mid+1

    print(f"get_ttl {ip} {port} {ans}")
    return ans
    

class GET_settings:
    def __init__(self):
        self.url = doh_server
        self.req = requests.session()              
        self.knocker_proxy = {'https': f'http://127.0.0.1:{DOH_PORT}'}
        


    def query_DNS(self,server_name,settings):     
        quary_params = {
            # 'name': server_name,    # no need for this when using dns wire-format , cause 400 err on some server
            'type': 'A',
            'ct': 'application/dns-message',
            }
        if settings["IPtype"]=="ipv6":
            quary_params['type']="AAAA";
        else:
            quary_params['type']="A";

        print(f'online DNS Query',server_name)        
        try:
            if settings["IPtype"]=="ipv6":
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
                    if ((settings["IPtype"] == "ipv6" and x.rdtype == dns.rdatatype.AAAA) or (settings["IPtype"] == "ipv4" and x.rdtype == dns.rdatatype.A)):
                        resolved_ip = x[0].address    # pick first ip in DNS answer
                        try:
                            if settings.get("IPcache")==False:
                                pass
                            else:
                                DNS_cache[server_name] = resolved_ip                        
                        except:    
                            DNS_cache[server_name] = resolved_ip                        
                        # print("################# DNS Cache is : ####################")
                        # print(DNS_cache)         # print DNS cache , it usefull to track all resolved IPs , to be used later.
                        # print("#####################################################")
                        break
                
                print(f'online DNS --> Resolved {server_name} to {resolved_ip}')                
                return resolved_ip
            else:
                print(f'Error DNS query: {ans.status_code} {ans.reason}')
            return "127.0.0.1"
        except Exception as e:
            print("ERROR DNS query: ",repr(e))
        return "ERROR"

    def query(self,domain, todns=True):
        # print("Query:",domain)
        res=domain_settings_tree.search("^"+domain+"$")
        # print(domain,'-->',sorted(res,key=lambda x:len(x),reverse=True)[0])
        try:
            res=copy.deepcopy(domain_settings.get(sorted(res,key=lambda x:len(x),reverse=True)[0]))
        except:
            res={}
        
        if todns==True:
            res.setdefault('IPtype', IPtype)

            if res.get("IP")==None:
                if DNS_cache.get(domain)!=None:
                    res["IP"]=DNS_cache[domain]
                else:
                    res["IP"]=self.query_DNS(domain,res)
                    if res["IP"]==None:
                        print("Failed to resolve domain, try again with other IP type")
                        if res["IPtype"]=="ipv6":                        
                            res["IPtype"]="ipv4"
                        elif res["IPtype"]=="ipv4":
                            res["IPtype"]="ipv6"
                        res["IP"]=self.query_DNS(domain,res)
                    lock_DNS_cache.acquire()
                    global cnt_dns_chg,dataPath
                    cnt_dns_chg=cnt_dns_chg+1
                    if cnt_dns_chg>=DNS_log_every:
                        cnt_dns_chg=0
                        
                        with dataPath.joinpath("DNS_cache.json").open('w', encoding='UTF-8') as f:
                            json.dump(DNS_cache,f)
                    lock_DNS_cache.release()

                res["IP"]=IPredirect(res.get("IP"))
                # res["IP"]="127.0.0.1"
        else:
            res["IP"]=todns
        res.setdefault('port', 443)

        res.setdefault('method', method)

        res.setdefault('TCP_frag', TCP_frag)
        res.setdefault('TCP_sleep', TCP_sleep)
        res.setdefault('num_TCP_fragment', num_TCP_fragment)

        if res.get("method")=="TLSfrag":
            res.setdefault('TLS_frag', TLS_frag)
            res.setdefault('num_TLS_fragment', num_TLS_fragment)
        elif res.get("method")=="FAKEdesync":
            res["FAKE_packet"] = FAKE_packet if res.get("FAKE_packet") is None else res["FAKE_packet"].encode(encoding='UTF-8')
            res.setdefault('FAKE_ttl', FAKE_ttl)
            res.setdefault('FAKE_sleep', FAKE_sleep)
            if res.get("FAKE_ttl")=="query":
                print(f'FAKE TTL for {res.get("IP")} is {res.get("FAKE_ttl")}')
                # print("Not implemented yet")
                # raise NotImplementedError
                if TTL_cache.get(res.get("IP"))!=None:
                    res["FAKE_ttl"]=TTL_cache[res.get("IP")]-1
                    print(f'FAKE TTL for {res.get("IP")} is {res.get("FAKE_ttl")}')
                else:
                    print(res.get("IP"),res.get("port"))
                    val=get_ttl(res.get("IP"),res.get("port"))
                    if val==-1:
                        raise Exception("ERROR get ttl")
                    TTL_cache[res.get("IP")]=val
                    res["FAKE_ttl"]=val-1
                    print(f'FAKE TTL for {res.get("IP")} is {res.get("FAKE_ttl")}')

                    lock_TTL_cache.acquire()
                    global cnt_ttl_chg
                    cnt_ttl_chg=cnt_ttl_chg+1
                    print(f"cnt_ttl_chg {cnt_ttl_chg}",TTL_log_every)
                    if cnt_ttl_chg>=TTL_log_every:
                        cnt_ttl_chg=0
                        with dataPath.joinpath("TTL_cache.json").open('w', encoding='UTF-8') as f:
                            json.dump(TTL_cache,f)
                    lock_TTL_cache.release()
        
        print(domain,'-->',res)
        return res
    

ThreadtoWork=False

class ThreadedServer(object):
    def __init__(self, host, port):
        self.DoH=GET_settings()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))


    def listen(self):
        self.sock.listen(128)  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.

        accept_thread = threading.Thread(target=self.accept_connections, args=())
        accept_thread.start()
        try:
            # 主程序逻辑
            while True:
                time.sleep(1)  # 主线程的其他操作
        except KeyboardInterrupt:
            # 捕获 Ctrl+C
            print("\nServer shutting down.")
        finally:
            #print('-- finally --')
            ThreadtoWork = False
            self.sock.close()

    def accept_connections(self):
        try:
            global ThreadtoWork
            while ThreadtoWork:
                client_sock, client_addr = self.sock.accept()
                client_sock.settimeout(my_socket_timeout)

                time.sleep(accept_time_sleep)   # avoid server crash on flooding request
                thread_up = threading.Thread(target = self.my_upstream, args = (client_sock,))
                thread_up.daemon = True   #avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
                thread_up.start()
            self.sock.close()
        except Exception as e:
            print(f'Server error: {e}')

    def handle_client_request(self,client_socket):
        # Receive the CONNECT request from the client
        data = client_socket.recv(16384)        

        if(data[:7]==b'CONNECT'):            
            server_name , server_port = self.extract_servername_and_port(data)      
        elif (data[:3]==b'GET' and str(data).split('\r\n')[0].split(' ')[1]=="/proxy.pac"):      
            # return pacfile
            response_data = f'HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {len(pacfile)}\r\n\r\n'+pacfile   
            
            client_socket.sendall(response_data.encode())
            client_socket.close()
            return None, {}
        elif( (data[:3]==b'GET') 
            or (data[:4]==b'POST') 
            or (data[:4]==b'HEAD')
            or (data[:7]==b'OPTIONS')
            or (data[:3]==b'PUT') 
            or (data[:6]==b'DELETE') 
            or (data[:5]==b'PATCH') 
            or (data[:5]==b'TRACE') ):  

            q_line = str(data).split('\r\n')
            q_req = q_line[0].split()
            q_method = q_req[0]
            q_url = q_req[1]
            q_url = q_url.replace('http://','https://')
            print('************************@@@@@@@@@@@@***************************')
            print('redirect',q_method,'http to HTTPS',q_url)          
            response_data = 'HTTP/1.1 302 Found\r\nLocation: '+q_url+'\r\nProxy-agent: MyProxy/1.0\r\n\r\n'            
            client_socket.sendall(response_data.encode())
            client_socket.close()            
            return None, {}
        else:
            print('Unknown Method',str(data[:10]))            
            response_data = b'HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
            client_socket.sendall(response_data)
            client_socket.close()            
            return None, {}

        
        print(server_name,'-->',server_port)

        try:
            try:
                ipaddress.ip_address(server_name)
                # print('legal IP')
                server_IP = server_name
                settings={}
                settings["IP"]=server_IP
            except ValueError:
                # print('Not IP , its domain , try to resolve it')
                settings=self.DoH.query(server_name)
                if settings==None:
                    settings={}
                settings["sni"]=bytes(server_name,encoding="utf-8")
                server_IP=settings.get("IP")
                server_port=settings.get("port")
                print("send to ",server_IP,":",server_port)

                
            if server_IP.find(":")==-1:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server_socket.settimeout(my_socket_timeout)
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   #force localhost kernel to send TCP packet immediately (idea: @free_the_internet)
            
            try:
                server_socket.connect((server_IP, server_port))
                # Send HTTP 200 OK
                response_data = b'HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n'            
                client_socket.sendall(response_data)
                return server_socket, settings
            except socket.error:
                print(f"@@@ {server_IP}:{server_port} ==> filtered @@@")
                # Send HTTP ERR 502
                response_data = b'HTTP/1.1 502 Bad Gateway (is IP filtered?)\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
                client_socket.sendall(response_data)
                client_socket.close()
                server_socket.close()
                return server_IP, {}

            
        except Exception as e:
            print(repr(e))
            # Send HTTP ERR 502
            response_data = b'HTTP/1.1 502 Bad Gateway (Strange ERR?)\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
            client_socket.sendall(response_data)
            client_socket.close()
            server_socket.close()
            return None, {}

    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock, settings = self.handle_client_request(client_sock)

        if(backend_sock==None):
            client_sock.close()
            return False
        
        if( isinstance(backend_sock,str) ):
            this_ip = backend_sock
            if(this_ip not in IP_UL_traffic):
                IP_UL_traffic[this_ip] = 0
                IP_DL_traffic[this_ip] = 0
            client_sock.close()
            return False

        
        this_ip = backend_sock.getpeername()[0]
        if(this_ip not in IP_UL_traffic):
            IP_UL_traffic[this_ip] = 0
            IP_DL_traffic[this_ip] = 0
        
        global ThreadtoWork
        while ThreadtoWork:
            try:
                if( first_flag == True ):                        
                    first_flag = False

                    time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)
                    # print(data)
                    #print('len data -> ',str(len(data)))                
                    #print('user talk :')

                    if data:                                                                                            
                        thread_down = threading.Thread(target = self.my_downstream , args = (backend_sock , client_sock, settings) )
                        thread_down.daemon = True
                        thread_down.start()
                        # backend_sock.sendall(data)    
                        try:
                            # print(settings)
                            if settings.get("sni")==None:
                                # print(data,parse_client_hello(data))
                                print("No sni? try to dig it in packet like gfwm ")
                                settings["sni"]=parse_client_hello(data)
                                tmp=settings.get("sni")
                                if settings["sni"]:
                                    settings=self.DoH.query(str(settings.get("sni")),todns=settings.get("IP"))
                                settings["sni"]=tmp
                        except Exception as e:
                            print(e)
                            import traceback
                            traceback_info = traceback.format_exc()
                            print(traceback_info)
                        if settings.get("method")=="TLSfrag":
                            send_data_in_fragment(settings.get("sni"),settings,data,backend_sock)
                        elif settings.get("method")=="FAKEdesync":
                            send_data_with_fake(settings.get("sni"),settings,data,backend_sock)
                        elif settings.get("method")=="DIRECT":
                            backend_sock.sendall(data)
                        elif settings.get("method")=="GFWlike":
                            client_sock.close()
                            backend_sock.close()
                            return False
                        else:
                            print("unknown method")
                            backend_sock.sendall(data)
                        IP_UL_traffic[this_ip] = IP_UL_traffic[this_ip] + len(data)

                    else:            
                        raise Exception('cli syn close')


                else:
                    data = client_sock.recv(16384)
                    # print(data)
                    if data:
                        backend_sock.sendall(data)  
                        IP_UL_traffic[this_ip] = IP_UL_traffic[this_ip] + len(data)                      
                    else:
                        raise Exception('cli pipe close')
                    
            except Exception as e:
                # import traceback
                # traceback_info = traceback.format_exc()
                # print(traceback_info)
                print('upstream : '+ repr(e) + 'from' , settings.get("sni") )
                time.sleep(2) # wait two second for another thread to flush
                client_sock.close()
                backend_sock.close()
                return False

        client_sock.close()
        backend_sock.close()

            
    def my_downstream(self, backend_sock , client_sock, settings):
        this_ip = backend_sock.getpeername()[0]        

        first_flag = True
        global ThreadtoWork
        while ThreadtoWork:
            try:
                if( first_flag == True ):
                    first_flag = False            
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                        IP_DL_traffic[this_ip] = IP_DL_traffic[this_ip] + len(data)
                    else:
                        raise Exception('backend pipe close at first')
                    
                else:
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                        IP_DL_traffic[this_ip] = IP_DL_traffic[this_ip] + len(data)
                    else:
                        raise Exception('backend pipe close')
            
            except Exception as e:
                print('downstream '+' : '+ repr(e) , settings.get("sni")) 
                time.sleep(2) # wait two second for another thread to flush
                backend_sock.close()
                client_sock.close()
                return False

        client_sock.close()
        backend_sock.close()


    def extract_servername_and_port(self,data):        
        host_and_port = str(data).split()[1]
        try:
            host,port = host_and_port.split(':')
        except:
            #ipv6
            if host_and_port.find('[')!=-1:
                host,port = host_and_port.split(']:')
                host=host[1:]
            else:
                idx=0
                for i in range(0,6):
                    idx=host_and_port.find(':',idx+1)
                host=host_and_port[:idx]
                port=host_and_port[idx+1:]
        return (host,int(port)) 

def parse_client_hello(data):
  import struct
  # print(struct.calcsize(">BHH"))
  # 解析TLS记录
  content_type, version_major, version_minor, length = struct.unpack(">BBBH", data[:5])
  if content_type!= 0x16:  # 0x16表示TLS Handshake
      raise ValueError("Not a TLS Handshake message")
  handshake_data = data[5:5 + length]

  # 解析握手消息头
  handshake_type, tmp, length = struct.unpack(">BBH", handshake_data[:4])
  length=tmp*64+length
  if handshake_type!= 0x01:  # 0x01表示Client Hello
      raise ValueError("Not a Client Hello message")
  client_hello_data = handshake_data[4:4 + length]

  # 解析Client Hello消息
  client_version_major, client_version_minor, random_bytes, session_id_length = struct.unpack(">BB32sB", client_hello_data[:35])
  session_id = client_hello_data[35:35 + session_id_length]
  # print(client_hello_data[35 + session_id_length:35 + session_id_length + 2])
  cipher_suites_length = struct.unpack(">H", client_hello_data[35 + session_id_length:35 + session_id_length + 2])[0]
  cipher_suites = client_hello_data[35 + session_id_length + 2:35 + session_id_length + 2 + cipher_suites_length]
  compression_methods_length = struct.unpack(">B", client_hello_data[35 + session_id_length + 2 + cipher_suites_length:35 + session_id_length + 2 + cipher_suites_length + 1])[0]
  compression_methods = client_hello_data[35 + session_id_length + 2 + cipher_suites_length + 1:35 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length]

  # 定位扩展部分
  extensions_offset = 35 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length
  extensions_length = struct.unpack(">H", client_hello_data[extensions_offset:extensions_offset + 2])[0]
  extensions_data = client_hello_data[extensions_offset + 2:extensions_offset + 2 + extensions_length]

  offset = 0
  while offset < extensions_length:
      extension_type, extension_length = struct.unpack(">HH", extensions_data[offset:offset + 4])
      if extension_type == 0x0000:  # SNI扩展的类型是0x0000
          sni_extension = extensions_data[offset + 4:offset + 4 + extension_length]
          # 解析SNI扩展
          list_length = struct.unpack(">H", sni_extension[:2])[0]
          if list_length!= 0:
              name_type, name_length = struct.unpack(">BH", sni_extension[2:5])
              if name_type == 0:  # 域名类型
                  sni = sni_extension[5:5 + name_length]
                  return sni
      offset += 4 + extension_length
  return None


def split_other_data(data, num_fragment, split):
    # print("sending: ", data)
    L_data = len(data)

    try:
        indices = random.sample(range(1,L_data-1), min(num_fragment,L_data-2))
    except:
        split(data)
        return 0
    indices.sort()
    # print('indices=',indices)

    i_pre=0
    for i in indices:
        fragment_data = data[i_pre:i]
        i_pre=i
        # sock.send(fragment_data)
        # print(fragment_data)
        split(new_frag=fragment_data)
        
    fragment_data = data[i_pre:L_data]
    split(fragment_data)

    return 1
# http114=b""

def split_data(data, sni, L_snifrag, num_fragment,split):
    stt=data.find(sni)
    if output_data:
        print(sni,stt)
    else:
        print("start of sni:",stt)

    if stt==-1:
        split_other_data(data, num_fragment, split)
        return 0,0

    L_sni=len(sni)
    L_data=len(data)

    if L_snifrag==0:
        split_other_data(data, num_fragment, split)
        return stt,stt+L_sni

    nstt=stt

    if split_other_data(data[0:stt+L_snifrag], num_fragment, split):
         nstt=nstt+num_fragment*5
    
    nst=L_snifrag

    while nst<=L_sni:
        fragment_data=data[stt+nst:stt+nst+L_snifrag]
        split(fragment_data)
        nst=nst+L_snifrag

    fraged_sni=data[stt:stt+nst]

    if split_other_data(data[stt+nst:L_data], num_fragment, split):
          nstt=nstt+num_fragment*5

    return nstt,int(nstt+nst+nst*5/L_snifrag)

def send_data_in_fragment(sni, settings, data , sock):
    print("To send: ",len(data)," Bytes. ")
    if sni==None:
        sock.sendall(data)
        return
    if output_data:
        print("sending:    ",data,"\n")
    base_header = data[:3]
    record=data[5:]
    TLS_ans=b""
    def TLS_add_frag(new_frag):
        nonlocal TLS_ans,base_header
        TLS_ans+=base_header + int.to_bytes(len(new_frag), byteorder='big', length=2)
        TLS_ans+=new_frag
        print("adding frag:",len(new_frag)," bytes. ")
        if output_data:
            print("adding frag: ",new_frag,"\n")
    stsni,edsni=split_data(record, sni, settings.get("TLS_frag"), settings.get("num_TLS_fragment"),TLS_add_frag)
    if edsni>0:
        first_sni_frag=TLS_ans[stsni:edsni]
    else: 
        first_sni_frag=b''

    print("TLS fraged: ",len(TLS_ans)," Bytes. ")
    if output_data:
        print("TLS fraged: ",TLS_ans,"\n")

    T_sleep=settings.get("TCP_sleep")
    def TCP_send_with_sleep(new_frag):
        nonlocal sock,T_sleep
        sock.sendall(new_frag)
        print("TCP send: ",len(new_frag)," bytes. And 'll sleep for ",T_sleep, "seconds. ")
        if output_data:
            print("TCP send: ",new_frag,"\n")
        time.sleep(T_sleep)
    split_data(TLS_ans, first_sni_frag, settings.get("TCP_frag"), settings.get("num_TCP_fragment"),TCP_send_with_sleep)
    
    print("----------finish------------",sni)
try:
    import platform
    if platform.system() == "Windows":

        import ctypes
        from ctypes import wintypes
        # 加载 mswsock.dll 库
        mswsock = ctypes.WinDLL('mswsock')
        # 加载 ws2_32.dll 库
        ws2_32 = ctypes.windll.ws2_32
        # 加载 kernel32.dll 库
        kernel32 = ctypes.windll.kernel32
        msvcrt = ctypes.cdll.msvcrt
        class _DUMMYSTRUCTNAME(ctypes.Structure):
          _fields_ = [
              ("Offset", wintypes.DWORD ),
              ("OffsetHigh", wintypes.DWORD ),
          ]
        # 定义 TransmitFile 函数的参数类型
        class _DUMMYUNIONNAME(ctypes.Union):
          _fields_ = [
              ("Pointer", ctypes.POINTER(ctypes.c_void_p)),
              ("DUMMYSTRUCTNAME", _DUMMYSTRUCTNAME),
          ]

        # class OVERLAPPED(ctypes.Structure):
        #     _fields_ = [
        #         ("Internal", wintypes.ULONG),
        #         ("InternalHigh", wintypes.ULONG),
        #         ("DUMMYUNIONNAME", _DUMMYUNIONNAME),
        #         ("hEvent", wintypes.HANDLE),
        #     ]

        class OVERLAPPED(ctypes.Structure):
          _fields_ = [
              ("Internal", ctypes.c_void_p),
              ("InternalHigh", ctypes.c_void_p),
              ("Offset", ctypes.c_ulong),
              ("OffsetHigh", ctypes.c_ulong),
              ("hEvent", ctypes.c_void_p)
          ]

        # import pywintypes 
        mswsock.TransmitFile.argtypes = [
          wintypes.HANDLE,  # 套接字句柄
          wintypes.HANDLE,  # 文件句柄
          wintypes.DWORD,  # 要发送的字节数
          wintypes.DWORD,  # 每次发送的字节数
          ctypes.POINTER(OVERLAPPED),  # 重叠结构指针
          ctypes.POINTER(ctypes.c_void_p),  # 传输缓冲区指针
          wintypes.DWORD  # 保留参数
        ]
        # 定义 TransmitFile 函数的返回值类型
        mswsock.TransmitFile.restype = wintypes.BOOL
        # ws2_32.WSASocketW.argtypes = [
        #     wintypes.INT, wintypes.INT, wintypes.INT,
        #     wintypes.DWORD,wintypes.DWORD, wintypes.DWORD
        # ]
        # ws2_32.WSASocketW.restype = ctypes.c_uint

        kernel32.CreateFileA.argtypes = [wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
        kernel32.CreateFileA.restype = wintypes.HANDLE
        kernel32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        kernel32.WriteFile.restype = wintypes.BOOL
        kernel32.SetFilePointer.argtypes = [wintypes.HANDLE, ctypes.c_long, wintypes.LONG, wintypes.DWORD]
        kernel32.SetFilePointer.restype = ctypes.c_long
        kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
        kernel32.SetEndOfFile.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        msvcrt._get_osfhandle.argtypes = [wintypes.INT]
        msvcrt._get_osfhandle.restype = wintypes.HANDLE
        # kernel32._get_osfhandle.argtypes = [wintypes.INT]
        # kernel32._get_osfhandle.restype = wintypes.HANDLE
        pass
    elif platform.system() in ('Linux', 'Darwin', 'Android'):
        import os
        import ctypes
        # 加载 libc 库
        
        try:
            libc = ctypes.CDLL('libc.so.6')
        except:
            libc=ctypes.CDLL('/system/lib64/libc.so')

        class iovec(ctypes.Structure):
            _fields_ = [
                ("iov_base", ctypes.c_void_p),
                ("iov_len", ctypes.c_size_t)
            ]


        # 定义 splice 函数的参数类型和返回类型
        libc.splice.argtypes = [
          ctypes.c_int,  # int fd_in
          ctypes.c_longlong,  # loff_t *off_in
          ctypes.c_int,  # int fd_out
          ctypes.c_longlong,  # loff_t *off_out
          ctypes.c_size_t,  # size_t len
          ctypes.c_uint  # unsigned int flags
        ]
        libc.splice.restype = ctypes.c_ssize_t


        # 定义 vmsplice 函数的参数类型和返回类型
        libc.vmsplice.argtypes = [
          ctypes.c_int,  # int fd
          ctypes.POINTER(iovec),  # struct iovec *iov
          ctypes.c_size_t,  # size_t nr_segs
          ctypes.c_uint  # unsigned int flags
        ]
        libc.vmsplice.restype = ctypes.c_ssize_t

        libc.mmap.argtypes = [
          ctypes.c_void_p,  # void *addr
          ctypes.c_size_t,  # size_t length
          ctypes.c_int,  # int prot
          ctypes.c_int,  # int flags
          ctypes.c_int,  # int fd
          ctypes.c_size_t  # off_t offset
        ]
        libc.mmap.restype = ctypes.c_void_p

        libc.memcpy.argtypes = [
        ctypes.c_void_p,  # void *dest
        ctypes.c_void_p,  # const void *src
        ctypes.c_size_t  # size_t n
        ]
        libc.memcpy.restype = ctypes.c_void_p
        libc.close.argtypes = [ctypes.c_int]
        libc.close.restype = ctypes.c_int
        

        libc.munmap.argtypes = [
        ctypes.c_void_p,  # void *addr
        ctypes.c_size_t  # size_t length
        ]
        libc.munmap.restype = ctypes.c_int

        libc.pipe.argtypes = [ctypes.POINTER(ctypes.c_int)]
        libc.pipe.restype = ctypes.c_int

        pass
except Exception as e:
  print(e)

def send_fake_data(data_len,fake_data,fake_ttl,real_data,default_ttl,sock,FAKE_sleep):
    import platform
    print(platform.system())
    if platform.system() == "Windows":
        print("desync on Windows may cause Error! Make sure other programs are not using the TransmitFile. ")
        """
        BOOL TransmitFile(
            SOCKET                  hSocket,
            HANDLE                  hFile,
            DWORD                   nNumberOfBytesToWrite,
            DWORD                   nNumberOfBytesPerSend,
            LPOVERLAPPED            lpOverlapped,
            LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
            DWORD                   dwReserved
        );
        """
        import tempfile,uuid
        file_path = f'{tempfile.gettempdir()}\\{uuid.uuid4()}.txt'
        try:
            sock_file_descriptor = sock.fileno()
            print("sock file discriptor:",sock_file_descriptor)
            # print("file path:",file_path)
            file_handle = kernel32.CreateFileA(
                bytes(file_path,encoding="utf-8"),
                wintypes.DWORD(0x40000000|0x80000000),  # GENERIC_READ | GENERIC_WRITE
                wintypes.DWORD(0x00000001|0x00000002),  # FILE_SHARE_READ | FILE_SHARE_WRITE
                None,
                wintypes.DWORD(2),  # CREATE_ALWAYS
                # 0,
                0x00000100, # FILE_FLAG_DELETE_ON_CLOSE
                None
            )

            if file_handle == -1:
                raise Exception("Create file failed, Error code:", kernel32.GetLastError())
            else:
                print("Create file success",file_handle)
            try:
                ov=OVERLAPPED()
                ov.hEvent=kernel32.CreateEventA(None,True,False,None)
                if ov.hEvent <= 0:
                    raise Exception("Create event failed, Error code:", kernel32.GetLastError())
                else:
                    print("Create event success",ov.hEvent)
                    
              

                kernel32.SetFilePointer(file_handle, 0, 0, 0)
                kernel32.WriteFile(file_handle, fake_data, data_len, ctypes.byref(wintypes.DWORD(0)), None)
                kernel32.SetEndOfFile(file_handle)
                set_ttl(sock,fake_ttl)
                kernel32.SetFilePointer(file_handle, 0, 0, 0)

                if output_data:
                    print(fake_data,real_data,data_len)

                # 调用 TransmitFile 函数
                result = mswsock.TransmitFile(
                    sock_file_descriptor,file_handle,
                    wintypes.DWORD(data_len),wintypes.DWORD(data_len),ov, None,
                    32 | 4 # TF_USE_KERNEL_APC | TF_WRITE_BEHIND
                )

                if FAKE_sleep<0.1:
                    print("Too short sleep time on Windows, set to 0.1")
                    FAKE_sleep=0.1

                print("sleep for: ",FAKE_sleep)
                time.sleep(FAKE_sleep)
                kernel32.SetFilePointer(file_handle, 0, 0, 0)
                kernel32.WriteFile(file_handle, real_data, data_len, ctypes.byref(wintypes.DWORD(0)) , None)
                kernel32.SetEndOfFile(file_handle)
                kernel32.SetFilePointer(file_handle, 0, 0, 0)
                set_ttl(sock,default_ttl)


                val=kernel32.WaitForSingleObject(ov.hEvent, wintypes.DWORD(5000))
                
                if val == 0:
                    # if result:
                    #     print("TransmitFile call was successful.")
                    # else:
                    #     raise Exception("TransmitFile call failed. Error code:", kernel32.GetLastError(),ws2_32.WSAGetLastError())
                    print("TransmitFile call was successful.",result)
                else:
                    raise Exception("TransmitFile call failed (on waiting for event). Error code:", kernel32.GetLastError(),ws2_32.WSAGetLastError())
                return True
            except:
                raise Exception("TransmitFile call failed. Error code:", kernel32.GetLastError())
            finally:                
                kernel32.CloseHandle(file_handle)
                kernel32.CloseHandle(ov.hEvent)
                import os
                os.remove(file_path)
        except Exception as e:
            raise e
    elif platform.system() in ('Linux', 'Darwin', 'Android'):
        try:
            sock_file_descriptor = sock.fileno()
            print("sock file discriptor:",sock_file_descriptor)
            fds=(ctypes.c_int * 2)()
            if libc.pipe(fds)<0:
                raise Exception("pipe creation failed")
            else:
                print("pipe creation success",fds[0],fds[1])
            p=libc.mmap(0,((data_len-1)//4+1)*4,0x1|0x2,0x2|0x20,0,0)# PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS
            if p==ctypes.c_void_p(-1):
                raise Exception("mmap failed")
            else:
                print("mmap success",p)
            libc.memcpy(p,fake_data,data_len)
            set_ttl(sock,fake_ttl)
            vec=iovec(p,data_len)
            len=libc.vmsplice(fds[1],ctypes.byref(vec),1,2)# SPLICE_F_GIFT
            if len<0:
                raise Exception("vmsplice failed")
            else:
                print("vmsplice success",len)
            len=libc.splice(fds[0],0,sock_file_descriptor,0,data_len,0)
            if len<0:
                raise Exception("splice failed")
            else:
                print("splice success",len)
            print("sleep for: ",FAKE_sleep)
            time.sleep(FAKE_sleep)
            libc.memcpy(p,real_data,data_len)
            set_ttl(sock,default_ttl)
            return True
        except Exception as e:
            raise e
        finally:
            libc.munmap(p,((data_len-1)//4+1)*4)
            libc.close(fds[0])
            libc.close(fds[1])
    else:
        raise Exception("unknown os")

def send_data_with_fake(sni, settings, data , sock):
    print("To send: ",len(data)," Bytes. ")
    
    if sni==None:
        sock.sendall(data)
        return
    # check os
    # if windows, use TransmitFile
    default_ttl=sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
    try:
        fake_data=settings.get("FAKE_packet")
        fake_ttl=int(settings.get("FAKE_ttl"))
    except:
        raise Exception("FAKE_packet or FAKE_ttl not set in settings.json")
    
    data_len=len(fake_data)
    FAKE_sleep=settings.get("FAKE_sleep")
    if send_fake_data(data_len,fake_data,fake_ttl,data[0:data_len],default_ttl,sock,FAKE_sleep):
        print("Fake data sent.")
    else:
        raise Exception("Fake data send failed.")

    data=data[data_len:]

    if data.find(sni)==-1:
        sock.sendall(data)
        return
    else:
        T_sleep=settings.get("TCP_sleep")
        first=True
        def TCP_send_with_sleep(new_frag):
            nonlocal sock,T_sleep,first
            # print(new_frag)
            len_new_frag=len(new_frag)
            
            if (len_new_frag==settings.get("TCP_frag")) & first: 
                # sock.sendall(new_frag)
                print(data[0:len_new_frag])
                try:
                    send_fake_data(len_new_frag,data[0:len_new_frag],fake_ttl,new_frag,default_ttl,sock,FAKE_sleep)
                except:
                    sock.sendall(new_frag)
                first=False
            else:
                sock.sendall(new_frag)
            print("TCP send: ",len(new_frag)," bytes. And 'll sleep for ",T_sleep, "seconds. ")
            if output_data:
                print("TCP send: ",new_frag,"\n")
            time.sleep(T_sleep)
        split_data(data, sni, settings.get("TCP_frag"), settings.get("num_TCP_fragment"),TCP_send_with_sleep)
        
    print("----------finish------------",sni)


serverHandle=None

def generate_PAC():
    global pac_domains,pacfile
    pacfile="""class TrieNode {
    constructor(value){
        this.value = value;
        this.num=1;
        this.deep=0;
        this.son=[];
        this.isEnd=false;
    }
    findNode(value){
        for(let i=0;i<this.son.length;i++){
            const node=this.son[i]
            if(node.value == value){
                return node;
            }
        }
        return null;
    }
}
class Trie {
    constructor(){
        this.root=new TrieNode(null);
        this.size=1;
    }
    insert(str){
        let node=this.root;
        for(let c of str){
            let snode = node.findNode(c);
            if(snode==null){
                snode=new TrieNode(c)
                snode.deep=node.deep+1;
                node.son.push(snode);
            }else{
                snode.num++;
            }
            node=snode;
 
        }
        
        if (!node.isEnd) {
            this.size++;
            node.isEnd = true;
        }
    }
    has(str){
        let node=this.root;
        for(let c of str){
            const snode=node.findNode(c)
            if(snode){
                node=snode;
            }else{
                return false;
            }
        }
        return node.isEnd;
    }
}

let tr=null;
function BuildAutomatom(arr) {
    
    tr=new Trie()
    arr.forEach(function (item) {
        tr.insert(item)
    })
    
    root=tr.root;
    root.fail=null;
    const queue=[root]
    let i=0;
    while(i<queue.length){
        const temp=queue[i];
        for(let j=0;j<temp.son.length;j++){
            const node=temp.son[j]
            if(temp===root){
                node.fail=root;
            }else{
                node.fail=temp.fail.findNode(node.value)||root;
            }
            queue.push(node);
        }
        i++
    }
}

function MatchAutomatom(str) {
    let node=tr.root;
    const data=[];
    for(let i=0;i<str.length;i++){
 
        let cnode=node.findNode(str[i])
        while(!cnode&&node!==tr.root){
            node=node.fail;
 
            cnode=node.findNode(str[i])
        }
        if(cnode){
            node=cnode;
        }
        if(node.isEnd){
            data.push({
                start:i+1-node.deep,
                len:node.deep,
                str:str.substr(i+1-node.deep,node.deep),
                num:node.num,
            })
        }
    }
    return data;
}

"""
    pacfile=pacfile+'let domains=[];\n'
    
    for line in pac_domains:
        pacfile=pacfile+'domains.push("'
        pacfile=pacfile+line
        pacfile=pacfile+'");\n'
    
    pacfile=pacfile+'BuildAutomatom(domains);\n'
    
    pacfile=pacfile+"""function FindProxyForURL(url, host) {
    if(MatchAutomatom("^"+host+"$").length)
         return "PROXY 127.0.0.1:"""
    pacfile+=str(listen_PORT)
    pacfile=pacfile+"""";
    else
        return "DIRECT";
}
"""

def start_server():
    global dataPath
    with dataPath.joinpath("config.json").open(mode='r', encoding='UTF-8') as f:
        global output_data,my_socket_timeout,FAKE_ttl_auto_timeout,listen_PORT,DOH_PORT,num_TCP_fragment,num_TLS_fragment,TCP_sleep,TCP_frag,TLS_frag,doh_server,domain_settings,DNS_log_every,TTL_log_every,IPtype,method,FAKE_packet,FAKE_ttl,FAKE_sleep,domain_settings_tree,pac_domains
        global ipv4trie,ipv6trie
        print(f"Now listening at: 127.0.0.1:{listen_PORT}")
        config = json.load(f)
        output_data=config.get("output_data")

        my_socket_timeout=config.get("my_socket_timeout")
        FAKE_ttl_auto_timeout=config.get("FAKE_ttl_auto_timeout")
        listen_PORT=config.get("listen_PORT")
        DOH_PORT=config.get("DOH_PORT")
        
        num_TCP_fragment=config.get("num_TCP_fragment")
        num_TLS_fragment=config.get("num_TLS_fragment")
        TCP_sleep=config.get("TCP_sleep")
        TCP_frag=config.get("TCP_frag")
        TLS_frag=config.get("TLS_frag")
        doh_server=config.get("doh_server")
        domain_settings=config.get("domains")
        DNS_log_every=config.get("DNS_log_every")
        TTL_log_every=config.get("TTL_log_every")
        IPtype=config.get("IPtype")
        method=config.get("method")
        FAKE_packet=config.get("FAKE_packet").encode(encoding='UTF-8')
        FAKE_ttl=config.get("FAKE_ttl")
        FAKE_sleep=config.get("FAKE_sleep")
        pac_domains=config.get("pac_domains")
        IPredirect=config.get("IPredirect")
        if FAKE_ttl=="auto":
            # temp code for auto fake_ttl
            FAKE_ttl=random.randint(10,60)
        generate_PAC()
        # print(set(domain_settings.keys()))
        domain_settings_tree= ahocorasick.AhoCorasick(*domain_settings.keys())
        for key in IPredirect.keys():
            if key.find(":")!=-1:
                ipv6trie.insert(ip_to_binary_prefix(key),IPredirect[key])
            else:
                ipv4trie.insert(ip_to_binary_prefix(key),IPredirect[key])

    try:
        global DNS_cache
        with dataPath.joinpath("DNS_cache.json").open(mode='r+', encoding='UTF-8') as f:
            DNS_cache=json.load(f)
    except Exception as e:
        print("ERROR DNS query: ",repr(e))

    try:
        global TTL_cache
        with dataPath.joinpath("TTL_cache.json").open(mode='r+', encoding='UTF-8') as f:
            TTL_cache=json.load(f)
    except Exception as e:
        print("ERROR TTL query: ",repr(e))
    
    global serverHandle
    serverHandle = ThreadedServer('',listen_PORT).listen()

def stop_server():
    global ThreadtoWork,proxythread
    ThreadtoWork=False
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1',listen_PORT))
    sock.close()
    while(proxythread.is_alive()):
        pass

def Write_DNS_cache():
    global DNS_cache,dataPath
    with dataPath.joinpath("DNS_cache.json").open(mode='w', encoding='UTF-8') as f:
        json.dump(DNS_cache,f)

def Write_TTL_cache():
    global TTL_cache,dataPath
    with dataPath.joinpath("TTL_cache.json").open(mode='w', encoding='UTF-8') as f:
        json.dump(TTL_cache,f)

dataPath=Path.cwd()

ThreadtoWork=True
proxythread=start_server()
