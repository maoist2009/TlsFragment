#!/usr/bin/env python3
# -*- coding: utf‑8 -*-

import asyncio, socket, time, random, copy, json, base64, ipaddress, struct
from pathlib import Path
import requests, threading, ahocorasick, dns.message, dns.rdatatype
import aiohttp, platform, ctypes, tempfile, uuid, os

# ------------------------------------------------------------------ #
#                          全局默认参数                               #
# ------------------------------------------------------------------ #
listen_PORT          = 2500
DOH_PORT             = 2500
log_every_N_sec      = 30
allow_insecure       = True
my_socket_timeout    = 120
FAKE_ttl_auto_timeout= 1
first_time_sleep     = 0.1
accept_time_sleep    = 0.01
output_data          = True
datapath             = Path()

domain_settings={
    "null": {
        "IP": "127.0.0.1",
        "TCP_frag": 114514,
        "TCP_sleep": 0.001,
        "TLS_frag": 114514,
        "num_TCP_fragment": 37,
        "num_TLS_fragment": 37,
        "method": "DIRECT"
    }
}
method="TLSfrag"
IPtype="ipv4"
num_TCP_fragment = 37
num_TLS_fragment = 37
TCP_sleep = 0.001
TCP_frag=0
TLS_frag=0
doh_server="https://127.0.0.1/dns-query"
DNS_log_every=1
TTL_log_every=1
FAKE_packet=b""
FAKE_ttl=10
FAKE_sleep=0.01

domain_settings_tree=None
DNS_cache,TTL_cache = {},{}
IP_DL_traffic,IP_UL_traffic = {},{}
cnt_dns_chg=cnt_ttl_chg=0
lock_DNS_cache=threading.Lock()
lock_TTL_cache=threading.Lock()
pac_domains=[]; pacfile="function genshin(){}"

# ------------------------------------------------------------------ #
#                            通用工具                                 #
# ------------------------------------------------------------------ #
def ip_to_binary_prefix(ip_or_network):
    try:
        network = ipaddress.ip_network(ip_or_network, strict=False)
        network_address = network.network_address
        prefix_length = network.prefixlen
        if isinstance(network_address, ipaddress.IPv4Address):
            binary_network = bin(int(network_address))[2:].zfill(32)
        else:
            binary_network = bin(int(network_address))[2:].zfill(128)
        return binary_network[:prefix_length]
    except ValueError:
        ip = ipaddress.ip_address(ip_or_network)
        binary_ip = bin(int(ip))[2:].zfill(32 if ip.version == 4 else 128)
        return binary_ip

class TrieNode:
    __slots__=('children','val')
    def __init__(self):
        self.children=[None,None]; self.val=None
class Trie:
    def __init__(self): self.root=TrieNode()
    def insert(self,prefix,value):
        node=self.root
        for bit in prefix:
            idx=int(bit)
            if not node.children[idx]: node.children[idx]=TrieNode()
            node=node.children[idx]
        node.val=value
    def search(self,prefix):
        node=self.root; ans=None
        for bit in prefix:
            idx=int(bit)
            if node.val is not None: ans=node.val
            if not node.children[idx]: return ans
            node=node.children[idx]
        return node.val if node.val is not None else ans
ipv4trie,ipv6trie=Trie(),Trie()

def set_ttl(sock,ttl):
    if sock.family==socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_UNICAST_HOPS,ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,ttl)

def tryipredirect(ip):
    if ":" in ip:
        ans=ipv6trie.search(ip_to_binary_prefix(ip)); return ip if ans is None else ans
    ans=ipv4trie.search(ip_to_binary_prefix(ip));     return ip if ans is None else ans

def IPredirect(ip):
    while True:
        ans=tryipredirect(ip)
        if ans==ip: break
        elif ans[0]=="^": print(f"IPredirect {ip} to {ans[1:]}"); ip=ans[1:]; break
        else: print(f"IPredirect {ip} to {ans}"); ip=ans
    return ip

# ------------------------------------------------------------------ #
#                TTL 侦测（原同步函数，保持不动）                      #
# ------------------------------------------------------------------ #
def check_ttl(ip,port,ttl):
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        set_ttl(sock,ttl); sock.settimeout(FAKE_ttl_auto_timeout)
        sock.connect((ip, port)); sock.send(b"0"); sock.close(); return True
    except Exception as e:
        print(e); return False
    finally:
        sock.close()

def get_ttl(ip,port):
    l,r,ans=1,128,-1
    while l<=r:
        mid=(l+r)//2
        val=check_ttl(ip,port,mid)
        print(l,r,mid,ans,val)
        if val: ans=mid; r=mid-1
        else:   l=mid+1
    print(f"get_ttl {ip} {port} {ans}")
    return ans

# ------------------------------------------------------------------ #
#               TLS 分片 / FAKE desync（原实现保持）                   #
# ------------------------------------------------------------------ #
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
          nstt+=num_fragment*5

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
    if platform.system()=="Windows":
        mswsock=ctypes.WinDLL('mswsock'); kernel32=ctypes.windll.kernel32; ws2_32=ctypes.windll.ws2_32
        class OVERLAPPED(ctypes.Structure):
            _fields_=[("Internal",ctypes.c_void_p),("InternalHigh",ctypes.c_void_p),
                      ("Offset",ctypes.c_ulong),("OffsetHigh",ctypes.c_ulong),
                      ("hEvent",ctypes.c_void_p)]
        file_path=f'{tempfile.gettempdir()}\\{uuid.uuid4()}.txt'
        fh=kernel32.CreateFileW(file_path,0x40000000|0x80000000,0x01|0x02,
                                None,2,0x00000100,None)
        if fh==-1: raise OSError("CreateFile failed")
        try:
            ov=OVERLAPPED(); ov.hEvent=kernel32.CreateEventW(None,True,False,None)
            kernel32.WriteFile(fh,fake_data,data_len,None,None); kernel32.SetEndOfFile(fh)
            set_ttl(sock,fake_ttl)
            mswsock.TransmitFile(sock.fileno(),fh,data_len,data_len,ctypes.byref(ov),None,0)
            time.sleep(max(FAKE_sleep,0.1))
            kernel32.SetFilePointer(fh,0,None,0)
            kernel32.WriteFile(fh,real_data,data_len,None,None); kernel32.SetEndOfFile(fh)
            set_ttl(sock,default_ttl)
            ws2_32.WSAWaitForMultipleEvents(1,ctypes.byref(ctypes.c_void_p(ov.hEvent)),True,5000,False)
            return True
        finally:
            kernel32.CloseHandle(fh); kernel32.CloseHandle(ov.hEvent); os.remove(file_path)
    else:
        libc=ctypes.CDLL('libc.so.6' if platform.system()!='Darwin' else 'libc.dylib')
        p=libc.valloc(data_len); libc.memcpy(p,fake_data,data_len)
        r,w=(ctypes.c_int*2)(); libc.pipe(r)
        set_ttl(sock,fake_ttl)
        libc.write(w[1],p,data_len)
        libc.sendfile(sock.fileno(),r[0],None,data_len)
        time.sleep(FAKE_sleep)
        libc.memcpy(p,real_data,data_len)
        set_ttl(sock,default_ttl)
        return True

def send_data_with_fake(sni, settings, data , sock):
    if sni is None: sock.sendall(data); return
    default_ttl=sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
    fake_data=settings["FAKE_packet"]; fake_ttl=int(settings["FAKE_ttl"])
    data_len=len(fake_data)
    send_fake_data(data_len,fake_data,fake_ttl,data[:data_len],default_ttl,sock,settings["FAKE_sleep"])
    rem=data[data_len:]
    def TCP_send(f): sock.sendall(f); time.sleep(settings["TCP_sleep"])
    split_data(rem,sni,settings["TCP_frag"],settings["num_TCP_fragment"],TCP_send)

# ------------------------------------------------------------------ #
#                      异步版 DoH 查询类                              #
# ------------------------------------------------------------------ #
class AsyncGET_settings:
    def __init__(self):
        self.url=doh_server.rstrip('/')+'/'; self.sess=None
    async def _ensure(self):
        if self.sess is None:
            self.sess=aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=allow_insecure))
    async def _wire(self,host,typ):
        await self._ensure()
        q=dns.message.make_query(host,typ).to_wire()
        url=self.url+'?dns='+base64.urlsafe_b64encode(q).rstrip(b'=').decode()
        async with self.sess.get(url,headers={'accept':'application/dns-message'}) as r:
            if r.status==200 and r.headers.get('content-type')=='application/dns-message':
                ans=dns.message.from_wire(await r.read())
                for rr in ans.answer:
                    if (typ=='A' and rr.rdtype==dns.rdatatype.A) or (typ=='AAAA' and rr.rdtype==dns.rdatatype.AAAA):
                        return rr[0].address
        return "127.0.0.1"
    async def query_DNS(self,server,settings):
        typ='AAAA' if settings["IPtype"]=='ipv6' else 'A'
        print("online DNS Query",server)
        ip=await self._wire(server,typ)
        DNS_cache[server]=ip
        return ip
    async def query(self,domain,todns=True):
        res=domain_settings_tree.search("^"+domain+"$")
        try:
            res=copy.deepcopy(domain_settings.get(sorted(res,key=len,reverse=True)[0]))
        except: res={}
        if todns is True:
            res.setdefault('IPtype',IPtype)
            if res.get("IP") is None:
                if DNS_cache.get(domain): res["IP"]=DNS_cache[domain]
                else: res["IP"]=await self.query_DNS(domain,res)
            res["IP"]=IPredirect(res["IP"])
        else: res["IP"]=todns
        res.setdefault('port',443); res.setdefault('method',method)
        res.setdefault('TCP_frag',TCP_frag); res.setdefault('TCP_sleep',TCP_sleep)
        res.setdefault('num_TCP_fragment',num_TCP_fragment)
        if res["method"]=="TLSfrag":
            res.setdefault('TLS_frag',TLS_frag); res.setdefault('num_TLS_fragment',num_TLS_fragment)
        elif res["method"]=="FAKEdesync":
            res["FAKE_packet"]=FAKE_packet if res.get("FAKE_packet") is None else res["FAKE_packet"].encode()
            res.setdefault('FAKE_ttl',FAKE_ttl); res.setdefault('FAKE_sleep',FAKE_sleep)
        print(domain,'-->',res); return res

# ------------------------------------------------------------------ #
#                  Async 版主服务器（替代多线程）                      #
# ------------------------------------------------------------------ #
class AsyncServer:
    def __init__(self,host,port):
        self.host,self.port=host,port; self.doh=AsyncGET_settings()
    async def _create_conn(self,name,port):
        try: ipaddress.ip_address(name); ip=name; settings={}
        except ValueError:
            settings=await self.doh.query(name); ip=settings["IP"]; port=settings.get("port",port)
            settings.setdefault("sni",name.encode())
        loop=asyncio.get_running_loop()
        family=socket.AF_INET6 if ':' in ip else socket.AF_INET
        s=socket.socket(family,socket.SOCK_STREAM); s.setblocking(False)
        try: await loop.sock_connect(s,(ip,port))
        except Exception as e: print("连接失败:",e); s.close(); return None,{}
        s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        return s,settings
    async def _proxy(self,cli,backend,settings):
        loop=asyncio.get_running_loop(); ip=backend.getpeername()[0]
        IP_UL_traffic.setdefault(ip,0); IP_DL_traffic.setdefault(ip,0)
        async def up():
            first=True
            try:
                while True:
                    data=await loop.sock_recv(cli,16384)
                    if not data: break
                    if first:
                        first=False; await asyncio.sleep(first_time_sleep)
                        m=settings["method"]
                        if m=="TLSfrag":
                            send_data_in_fragment(settings["sni"],settings,data,backend)
                        elif m=="FAKEdesync":
                            send_data_with_fake(settings["sni"],settings,data,backend)
                        elif m=="GFWlike":
                            cli.close(); backend.close(); return
                        else:      # DIRECT 或 其它未知 => 直接透传
                            await loop.sock_sendall(backend,data)
                    else:
                        await loop.sock_sendall(backend,data)
                    IP_UL_traffic[ip]+=len(data)
            finally:
                cli.close(); backend.close()
        async def down():
            try:
                while True:
                    data=await loop.sock_recv(backend,16384)
                    if not data: break
                    await loop.sock_sendall(cli,data)
                    IP_DL_traffic[ip]+=len(data)
            finally:
                cli.close(); backend.close()
        await asyncio.gather(up(),down())
    async def _handle(self,cli):
        loop=asyncio.get_running_loop()
        try:
            peek=await loop.sock_recv(cli,1)
            if not peek: cli.close(); return
            if peek==b'\x05':  # SOCKS5
                await loop.sock_recv(cli,1)           # NMETHODS
                await loop.sock_recv(cli,1)           # METHOD (长度1)
                await loop.sock_sendall(cli,b'\x05\x00')
                hdr=await loop.sock_recv(cli,4)
                if hdr[1]!=0x01: cli.close(); return
                atyp=hdr[3]
                if   atyp==0x01: host=socket.inet_ntop(socket.AF_INET,await loop.sock_recv(cli,4))
                elif atyp==0x04: host=socket.inet_ntop(socket.AF_INET6,await loop.sock_recv(cli,16))
                else:            ln=(await loop.sock_recv(cli,1))[0]; host=(await loop.sock_recv(cli,ln)).decode()
                port=int.from_bytes(await loop.sock_recv(cli,2),'big')
                backend,settings=await self._create_conn(host,port)
                if backend is None: cli.close(); return
                await loop.sock_sendall(cli,b'\x05\x00\x00\x01'+socket.inet_aton("0.0.0.0")+b'\x00\x00')
                await self._proxy(cli,backend,settings)
            else:                 # HTTP
                data=peek+await loop.sock_recv(cli,16384)
                if data.startswith(b'CONNECT'):
                    hp=data.split()[1].decode()
                    host,port=(hp.split(':') if hp.count(':')==1 else (hp.strip('[]').rsplit(':',1)))
                    backend,settings=await self._create_conn(host,int(port))
                    if backend is None:
                        await loop.sock_sendall(cli,b'HTTP/1.1 502 Bad Gateway\r\n\r\n'); cli.close(); return
                    await loop.sock_sendall(cli,b'HTTP/1.1 200 Connection established\r\n\r\n')
                    remain=data.split(b'\r\n\r\n',1)[1]
                    if remain: await loop.sock_sendall(backend,remain)
                    await self._proxy(cli,backend,settings)
                elif b'/proxy.pac' in data.splitlines()[0]:
                    resp=f'HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {len(pacfile)}\r\n\r\n{pacfile}'
                    await loop.sock_sendall(cli,resp.encode()); cli.close()
                elif data[:3] in (b'GET',b'POS',b'HEA',b'PUT',b'DEL') or data[:4] in (b'POST',b'HEAD',b'OPTI'):
                    q=data.decode(errors='ignore').split('\r\n')[0].split()[1]
                    if q.startswith('http://'):
                        https=q.replace('http://','https://',1)
                        resp=f'HTTP/1.1 302 Found\r\nLocation: {https}\r\n\r\n'
                        await loop.sock_sendall(cli,resp.encode())
                    cli.close()
                else:
                    await loop.sock_sendall(cli,b'HTTP/1.1 400 Bad Request\r\n\r\n'); cli.close()
        except Exception as e:
            print("handle error:",e); cli.close()
    async def start(self):
        srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        srv.bind((self.host,self.port)); srv.listen(256); srv.setblocking(False)
        loop=asyncio.get_running_loop()
        print(f"Now listening at: 127.0.0.1:{self.port}")
        while True:
            cli,_=await loop.sock_accept(srv); cli.setblocking(False)
            await asyncio.sleep(accept_time_sleep)
            loop.create_task(self._handle(cli))

# ------------------------------------------------------------------ #
#                            PAC 生成                                 #
# ------------------------------------------------------------------ #
def generate_PAC():
    global pacfile
    pacfile="""function FindProxyForURL(url,host){var a=["""+','.join(f'"{d}"' for d in pac_domains)+"""];for(var i=0;i<a.length;i++){if(host==a[i])return"PROXY 127.0.0.1:"""+str(listen_PORT)+""";}return"DIRECT";}"""

# ------------------------------------------------------------------ #
#                       配置读取并启动                                #
# ------------------------------------------------------------------ #
def load_config():
    global output_data,my_socket_timeout,FAKE_ttl_auto_timeout,listen_PORT,DOH_PORT
    global num_TCP_fragment,num_TLS_fragment,TCP_sleep,TCP_frag,TLS_frag,doh_server
    global domain_settings,DNS_log_every,TTL_log_every,IPtype,method
    global FAKE_packet,FAKE_ttl,FAKE_sleep,domain_settings_tree,pac_domains
    global ipv4trie,ipv6trie
    cfg_file=datapath/'config.json'
    if not cfg_file.exists(): return
    cfg=json.loads(cfg_file.read_text(encoding='utf-8'))
    output_data          =cfg.get("output_data",output_data)
    my_socket_timeout    =cfg.get("my_socket_timeout",my_socket_timeout)
    FAKE_ttl_auto_timeout=cfg.get("FAKE_ttl_auto_timeout",FAKE_ttl_auto_timeout)
    listen_PORT          =cfg.get("listen_PORT",listen_PORT)
    DOH_PORT             =cfg.get("DOH_PORT",DOH_PORT)
    num_TCP_fragment     =cfg.get("num_TCP_fragment",num_TCP_fragment)
    num_TLS_fragment     =cfg.get("num_TLS_fragment",num_TLS_fragment)
    TCP_sleep            =cfg.get("TCP_sleep",TCP_sleep)
    TCP_frag             =cfg.get("TCP_frag",TCP_frag)
    TLS_frag             =cfg.get("TLS_frag",TLS_frag)
    doh_server           =cfg.get("doh_server",doh_server)
    domain_settings      =cfg.get("domains",domain_settings)
    DNS_log_every        =cfg.get("DNS_log_every",DNS_log_every)
    TTL_log_every        =cfg.get("TTL_log_every",TTL_log_every)
    IPtype               =cfg.get("IPtype",IPtype)
    method               =cfg.get("method",method)
    FAKE_packet          =cfg.get("FAKE_packet","").encode()
    FAKE_ttl             =cfg.get("FAKE_ttl",FAKE_ttl)
    FAKE_sleep           =cfg.get("FAKE_sleep",FAKE_sleep)
    pac_domains          =cfg.get("pac_domains",[])
    for k,v in cfg.get("IPredirect",{}).items():
        (ipv6trie if ':' in k else ipv4trie).insert(ip_to_binary_prefix(k),v)
    generate_PAC()
    domain_settings_tree=ahocorasick.AhoCorasick(*domain_settings.keys())

def main():
    load_config()
    server=AsyncServer('0.0.0.0',listen_PORT)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("Server stopped.")

if __name__=="__main__":
    main()