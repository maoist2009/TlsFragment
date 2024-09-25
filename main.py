#!/usr/bin/env python3
import requests      #  --> pip install requests
from pathlib import Path
import os
import base64
import socket
import threading
import time
import random


listen_PORT = 2500    # pyprox listening to 127.0.0.1:listen_PORT

num_fragment = 87  # total number of chunks that ClientHello devided into (chunks with random size)
fragment_sleep = 0.005  # sleep between each fragment to make GFW-cache full so it forget previous chunks. LOL.

log_every_N_sec = 30   # every 30 second , update log file with latest DNS-cache statistics

allow_insecure = True   # set true to allow certificate domain mismatch in DoH



DNS_url = 'https://cloudflare-dns.com/dns-query?dns='
# DNS_url = 'https://8.8.4.4/dns-query?dns='      # blocked?
# DNS_url = 'https://8.8.8.8/dns-query?dns='      # blocked?
# DNS_url = 'https://1.1.1.1/dns-query?dns='      # blocked?
# DNS_url = 'https://dns.google/dns-query?dns='              # blocked?
# DNS_url = 'https://doh.opendns.com/dns-query?dns='           # blocked?
# DNS_url = 'https://secure.avastdns.com/dns-query?dns='      # blocked?
# DNS_url = 'https://doh.libredns.gr/dns-query?dns='          # blocked?
# DNS_url = 'https://dns.electrotm.org/dns-query?dns='        # DNS server inside iran
# DNS_url = 'https://dns.bitdefender.net/dns-query?dns='
# DNS_url = 'https://cluster-1.gac.edu/dns-query?dns='




domain_settings={
    "www.pixiv.net": {
        "IP": "104.19.112.154",
        "frag": 5,
        "sleep": 0.3
    },
    "accounts.pixiv.net": {
        "IP": "104.19.112.154",
        "frag": 3,
        "sleep": 0.3
    },
    "null": 
    {
        "IP": "127.0.0.1",
        "frag": 114514,
        "sleep": 0.001
    }
}





# ignore description below , its for old code , just leave it intact.
my_socket_timeout = 8 # default for google is ~21 sec , recommend 60 sec unless you have low ram and need close soon
first_time_sleep = 0.1 # speed control , avoid server crash if huge number of users flooding
accept_time_sleep = 0.01 # avoid server crash on flooding request -> max 100 sockets per second


DNS_cache = {}      # resolved domains
IP_DL_traffic = {}  # download usage for each ip
IP_UL_traffic = {}  # upload usage for each ip
        

def query_settings(domain):
    return domain_settings.get(domain)





class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sni = ""
        self.settings = {
            "IP": "127.0.0.1",
            "frag": 114514,
            "sleep": 0.001
        }

    def listen(self):
        self.sock.listen(128)  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.
                        
        while True:
            client_sock , client_addr = self.sock.accept()                    
            client_sock.settimeout(my_socket_timeout)
                        
            time.sleep(accept_time_sleep)   # avoid server crash on flooding request
            thread_up = threading.Thread(target = self.my_upstream , args =(client_sock,) )
            thread_up.daemon = True   #avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
            thread_up.start()
    


    def handle_client_request(self,client_socket):
        # Receive the CONNECT request from the client
        data = client_socket.recv(16384)
        

        if(data[:7]==b'CONNECT'):            
            server_name , server_port = self.extract_servername_and_port(data)            
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
            return None
        else:
            print('Unknown Method',str(data[:10]))            
            response_data = b'HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
            client_socket.sendall(response_data)
            client_socket.close()            
            return None

        
        print(server_name,'-->',server_port)
        self.sni=server_name

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(my_socket_timeout)
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   #force localhost kernel to send TCP packet immediately (idea: @free_the_internet)

            try:
                socket.inet_aton(server_name)
                # print('legal IP')
                server_IP = server_name
            except socket.error:
                # print('Not IP , its domain , try to resolve it')
                self.settings=query_settings(server_name)
                if self.settings==None:                    
                    self.settings="127.0.0.1"
                server_IP=self.settings.get("IP")
            

            try:
                server_socket.connect((server_IP, server_port))
                # Send HTTP 200 OK
                response_data = b'HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n'            
                client_socket.sendall(response_data)
                return server_socket
            except socket.error:
                print("@@@ "+server_IP+":"+str(server_port)+ " ==> filtered @@@")
                # Send HTTP ERR 502
                response_data = b'HTTP/1.1 502 Bad Gateway (is IP filtered?)\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
                client_socket.sendall(response_data)
                client_socket.close()
                server_socket.close()
                return server_IP

            
        except Exception as e:
            print(repr(e))
            # Send HTTP ERR 502
            response_data = b'HTTP/1.1 502 Bad Gateway (Strange ERR?)\r\nProxy-agent: MyProxy/1.0\r\n\r\n'
            client_socket.sendall(response_data)
            client_socket.close()
            server_socket.close()
            return None







    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock = self.handle_client_request(client_sock)

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
        
        
        while True:
            try:
                if( first_flag == True ):                        
                    first_flag = False

                    time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)
                    #print('len data -> ',str(len(data)))                
                    #print('user talk :')

                    if data:                                                                                            
                        thread_down = threading.Thread(target = self.my_downstream , args = (backend_sock , client_sock) )
                        thread_down.daemon = True
                        thread_down.start()
                        # backend_sock.sendall(data)    
                        send_data_in_fragment(self.sni,self.settings,data,backend_sock)
                        IP_UL_traffic[this_ip] = IP_UL_traffic[this_ip] + len(data)

                    else:                   
                        raise Exception('cli syn close')

                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.sendall(data)  
                        IP_UL_traffic[this_ip] = IP_UL_traffic[this_ip] + len(data)                      
                    else:
                        raise Exception('cli pipe close')
                    
            except Exception as e:
                #print('upstream : '+ repr(e) )
                time.sleep(2) # wait two second for another thread to flush
                client_sock.close()
                backend_sock.close()
                return False



            
    def my_downstream(self, backend_sock , client_sock):
        this_ip = backend_sock.getpeername()[0]        

        first_flag = True
        while True:
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
                #print('downstream '+backend_name +' : '+ repr(e)) 
                time.sleep(2) # wait two second for another thread to flush
                backend_sock.close()
                client_sock.close()
                return False



    def extract_servername_and_port(self,data):        
        host_and_port = str(data).split()[1]
        host,port = host_and_port.split(':')
        return (host,int(port)) 






def send_other_data_in_fragment(data , sock):
    # print("send: ", data)
    L_data = len(data)
    if L_data<num_fragment: 
        num_fragment=L_data
    indices = random.sample(range(1,L_data-1), num_fragment-1)
    indices.sort()
    # print('indices=',indices)

    i_pre=0
    for i in indices:
        fragment_data = data[i_pre:i]
        i_pre=i
        print('send ',len(fragment_data),' bytes')                        
        
        # sock.send(fragment_data)
        sock.sendall(fragment_data)
        
        time.sleep(fragment_sleep)
    
    fragment_data = data[i_pre:L_data]
    sock.sendall(fragment_data)

def send_data_in_fragment(sni, settings, data , sock):
    # print(data)
    data=str(data)
    stt=data.find(sni)

    L_sni=len(sni)
    L_snifrag=settings.get("frag");
    T_sleep=settings.get("sleep");
    L_data=len(data)

    send_other_data_in_fragment(data[0:stt+L_snifrag],sock)
    time.sleep(T_sleep)

    nst=L_snifrag

    print(nst)

    while nst<=L_sni:
        print("send: ",data[stt+nst:stt+nst+L_snifrag])
        sock.sendall(data[stt+nst:stt+nst+L_snifrag])
        nst=nst+L_snifrag
        time.sleep(T_sleep)

    send_other_data_in_fragment(data[stt+nst:L_data])

    print('----------finish------------')




if (__name__ == "__main__"):
    print ("Now listening at: 127.0.0.1:"+str(listen_PORT))
    ThreadedServer('',listen_PORT).listen()