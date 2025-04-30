from .log import logger
from pathlib import Path
import socket
import threading
import time
from . import remote, fake_desync
from .config import config
from .utils import is_ip_address
from .safecheck import detect_tls_version_by_keyshare
import json

my_socket_timeout = 120  # default for google is ~21 sec , recommend 60 sec unless you have low ram and need close soon

datapath = Path()

domain_settings = {
    "null": {
        "IP": "127.0.0.1",
        "TCP_frag": 114514,
        "TCP_sleep": 0.001,
        "TLS_frag": 114514,
        "num_TCP_fragment": 37,
        "num_TLS_fragment": 37,
    }
}


TTL_cache = {}  # TTL for each IP
IP_DL_traffic = {}  # download usage for each ip
IP_UL_traffic = {}  # upload usage for each ip

lock_TTL_cache = threading.Lock()
pac_domains = []
pacfile = "function genshin(){}"

ThreadtoWork = False

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(
            128
        )  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.

        accept_thread = threading.Thread(target=self.accept_connections, args=())
        accept_thread.start()
        try:
            # 主程序逻辑
            while True:
                time.sleep(1)  # 主线程的其他操作
        except KeyboardInterrupt:
            # 捕获 Ctrl+C
            logger.warning("\nServer shutting down.")
        finally:
            ThreadtoWork = False
            self.sock.close()

    def accept_connections(self):
        try:
            global ThreadtoWork
            while ThreadtoWork:
                client_sock, _ = self.sock.accept()
                client_sock.settimeout(my_socket_timeout)

                time.sleep(0.01)  # avoid server crash on flooding request
                thread_up = threading.Thread(
                    target=self.my_upstream, args=(client_sock,)
                )
                thread_up.daemon = True  # avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
                thread_up.start()
            self.sock.close()
        except Exception as e:
            logger.warning("Server error: %s", e)

    def handle_client_request(self, client_socket):
        try:
            # 协议嗅探（兼容原有逻辑）
            initial_data = client_socket.recv(5, socket.MSG_PEEK)
            if not initial_data:
                client_socket.close()
                return None, {}

            # 协议分流判断
            if initial_data[0] == 0x05:  # SOCKS5协议
                return self._handle_socks5(client_socket)
            else:  # HTTP协议处理
                return self._handle_http_protocol(client_socket)

        except Exception as e:
            logger.error("协议检测异常: %s", e)
            client_socket.close()
            return None, {}

    def _handle_socks5(self, client_socket):
        """处理SOCKS5协议连接，保持与原有返回格式一致"""
        try:
            # 认证协商阶段
            client_socket.recv(2)  # 已经通过peek确认版本
            nmethods = client_socket.recv(1)[0]
            if nmethods==0:
                nmethods=1
            client_socket.recv(nmethods)  # 读取方法列表
            client_socket.sendall(b"\x05\x00")  # 选择无认证

            # 请求解析阶段
            header = client_socket.recv(4)
            print(header)
            if len(header) != 4 or header[0] != 0x05:
                raise ValueError("Invalid SOCKS5 header")

            _, cmd, _, atyp = header
            if cmd != 0x01:  # 只支持CONNECT命令
                client_socket.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                return None, {}

            # 目标地址解析（复用原有DNS逻辑）
            server_name, server_port = self._parse_socks5_address(client_socket, atyp)
            
            print(server_name,server_port)

            # 建立连接（完全复用原有逻辑）
            try:
                remote_obj = remote.Remote(server_name, server_port)
                client_socket.sendall(
                    b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {str(e)}")
                client_socket.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                return server_name if is_ip_address(server_name) else None, {}

        except Exception as e:
            logger.info(f"SOCKS5处理错误: {str(e)}")
            client_socket.close()
            return None, {}

    def _handle_http_protocol(self, client_socket):
        """原有HTTP处理逻辑完整保留"""
        data = client_socket.recv(16384)

        # 原有CONNECT处理
        if data.startswith(b"CONNECT"):
            server_name, server_port = self.extract_servername_and_port(data)
            logger.info(f"CONNECT {server_name}:{server_port}")

            try:
                remote_obj = remote.Remote(server_name, server_port)
                client_socket.sendall(
                    b"HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {str(e)}")
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return server_name if is_ip_address(server_name) else None, {}

        # 原有PAC文件处理
        elif b"/proxy.pac" in data.splitlines()[0]:
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {len(pacfile)}\r\n\r\n{pacfile}"
            client_socket.sendall(response.encode())
            client_socket.close()
            return None, {}

        # 原有HTTP重定向逻辑
        elif data[:3] in (b"GET", b"POS", b"HEA", b"PUT", b"DEL") or data[:4] in (
            b"POST",
            b"HEAD",
            b"OPTI",
        ):
            q_line = data.decode().split("\r\n")[0].split()
            q_method, q_url = q_line[0], q_line[1]
            https_url = q_url.replace("http://", "https://", 1)
            logger.info(f"重定向 {q_method} 到 HTTPS: {https_url}")
            response = f"HTTP/1.1 302 Found\r\nLocation: {https_url}\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
            client_socket.sendall(response.encode())
            client_socket.close()
            return None, {}

        # 原有错误处理
        else:
            logger.info(f"未知请求: {data[:10]}")
            client_socket.sendall(
                b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
            )
            client_socket.close()
            return None, {}

    def _parse_socks5_address(self, sock, atyp):
        """SOCKS5地址解析"""
        if atyp == 0x01:  # IPv4
            server_ip = socket.inet_ntop(socket.AF_INET, sock.recv(4))
            return server_ip, int.from_bytes(sock.recv(2), "big")
        elif atyp == 0x03:  # 域名
            domain_len = ord(sock.recv(1))
            server_name = sock.recv(domain_len).decode()
            port = int.from_bytes(sock.recv(2), "big")
            return server_name, port
        elif atyp == 0x04:  # IPv6
            server_ip = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
            return server_ip, int.from_bytes(sock.recv(2), "big")
        else:
            raise ValueError("Invalid address type")

    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock = self.handle_client_request(client_sock)
        try:
            backend_sock.connect()
        except:
            logger.error("connect failed")
            return False

        if backend_sock == None:
            client_sock.close()
            return False

        if isinstance(backend_sock, str):
            this_ip = backend_sock
            if this_ip not in IP_UL_traffic:
                IP_UL_traffic[this_ip] = 0
                IP_DL_traffic[this_ip] = 0
            client_sock.close()
            return False

        this_ip = backend_sock.sock.getpeername()[0]
        if this_ip not in IP_UL_traffic:
            IP_UL_traffic[this_ip] = 0
            IP_DL_traffic[this_ip] = 0

        global ThreadtoWork
        while ThreadtoWork:
            try:
                if first_flag is True:
                    first_flag = False

                    time.sleep(
                        0.1
                    )  # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)

                    if data:
                        thread_down = threading.Thread(
                            target=self.my_downstream,
                            args=(backend_sock, client_sock),
                        )
                        thread_down.daemon = True
                        thread_down.start()
                        # backend_sock.sendall(data)
                        if backend_sock.policy.get("mode") == "TLSfrag":
                            backend_sock.send(data)
                        elif backend_sock.policy.get("mode") == "FAKEdesync":
                            fake_desync.send_data_with_fake(
                                backend_sock,
                                data,
                            )
                        IP_UL_traffic[this_ip] += len(data)

                    else:
                        raise Exception("cli syn close")

                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.send(data)
                        IP_UL_traffic[this_ip] += len(data)
                    else:
                        raise Exception("cli pipe close")

            except Exception as e:
                logger.info("upstream : %s from %s", repr(e), backend_sock.domain)
                time.sleep(2)  # wait two second for another thread to flush
                client_sock.close()
                backend_sock.sock.close()
                return False

        client_sock.close()
        backend_sock.sock.close()

    def my_downstream(self, backend_sock: remote.Remote, client_sock: socket.socket):
        this_ip = backend_sock.sock.getpeername()[0]

        first_flag = True
        global ThreadtoWork
        while ThreadtoWork:
            try:
                if first_flag is True:
                    first_flag = False
                    data = backend_sock.recv(16384)
                    if True:
                        try:
                            if detect_tls_version_by_keyshare(data)<0:
                                backend_sock.sock.close()
                                client_sock.close()
                                raise ValueError("Not a TLS 1.3 connection")
                        except:
                            pass              
                    if data:
                        client_sock.sendall(data)
                        IP_DL_traffic[this_ip] += len(data)
                    else:
                        raise Exception("backend pipe close at first")

                else:
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                        IP_DL_traffic[this_ip] += len(data)
                    else:
                        raise Exception("backend pipe close")

            except Exception as e:
                logger.info("downstream : %s %s", repr(e), backend_sock.domain)
                time.sleep(2)  # wait two second for another thread to flush
                backend_sock.sock.close()
                client_sock.close()
                return False

        client_sock.close()
        backend_sock.close()

    def extract_servername_and_port(self, data):
        host_and_port = str(data).split()[1]
        try:
            host, port = host_and_port.split(":")
        except:
            # ipv6
            if host_and_port.find("[") != -1:
                host, port = host_and_port.split("]:")
                host = host[1:]
            else:
                idx = 0
                for _ in range(0, 6):
                    idx = host_and_port.find(":", idx + 1)
                host = host_and_port[:idx]
                port = host_and_port[idx + 1 :]
        return (host, int(port))


# http114=b""


serverHandle = None


def generate_PAC():
    global pac_domains, pacfile
    pacfile = """class TrieNode {
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
    pacfile += "let domains=[];\n"

    for line in pac_domains:
        pacfile += 'domains.push("'
        pacfile += line
        pacfile += '");\n'

    pacfile += "BuildAutomatom(domains);\n"

    pacfile = (
        pacfile
        + """function FindProxyForURL(url, host) {
    if(MatchAutomatom("^"+host+"$").length)
         return "PROXY 127.0.0.1:"""
    )
    pacfile += str(config["port"])
    pacfile = (
        pacfile
        + """";
    else
        return "DIRECT";
}
"""
    )


def start_server():
    global dataPath
    with dataPath.joinpath("config.json").open(mode="r", encoding="UTF-8") as f:
        generate_PAC()

    try:
        global TTL_cache
        with dataPath.joinpath("TTL_cache.json").open(mode="r+", encoding="UTF-8") as f:
            TTL_cache = json.load(f)
    except Exception as e:
        logger.info("ERROR TTL query: %s", repr(e))

    global serverHandle
    logger.info(f"Now listening at: 127.0.0.1:{config['port']}")
    serverHandle = ThreadedServer("", config["port"]).listen()


def stop_server():
    global ThreadtoWork, proxythread
    ThreadtoWork = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", config["port"]))
    sock.close()
    while proxythread.is_alive():
        pass


def Write_TTL_cache():
    global TTL_cache, dataPath
    with dataPath.joinpath("TTL_cache.json").open(mode="w", encoding="UTF-8") as f:
        json.dump(TTL_cache, f)


dataPath = Path.cwd()
ThreadtoWork = True

if __name__ == "__main__":
    proxythread = start_server()
