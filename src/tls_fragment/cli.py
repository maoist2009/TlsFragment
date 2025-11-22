from .log import logger
from pathlib import Path
import socket
import threading
import time
from . import remote, fake_desync, fragment, utils
from .config import config
from .remote import match_domain
from .pac import generate_pac, load_pac

datapath = Path()

pacfile = "function genshin(){}"

ThreadtoWork = False
proxy_thread = None

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self,block=True):
        global ThreadtoWork, proxy_thread
        self.sock.listen(
            128
        )  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.

        proxy_thread = threading.Thread(target=self.accept_connections, args=())
        proxy_thread.start()
        if block:
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
        else:
            return self

    def accept_connections(self):
        try:
            global ThreadtoWork
            while ThreadtoWork:
                client_sock, _ = self.sock.accept()
                client_sock.settimeout(config["my_socket_timeout"])

                time.sleep(0.01)  # avoid server crash on flooding request
                thread_up = threading.Thread(
                    target=self.my_upstream, args=(client_sock,)
                )
                thread_up.daemon = True  # avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
                thread_up.start()
            self.sock.close()
        except Exception as e:
            logger.warning(f"Server error: {repr(e)}")

    def handle_client_request(self, client_socket):
        try:
            # 协议嗅探（兼容原有逻辑）
            initial_data = client_socket.recv(5, socket.MSG_PEEK)
            if not initial_data:
                client_socket.close()
                return None

            # 协议分流判断
            if initial_data[0] == 0x05:  # SOCKS5协议
                return self._handle_socks5(client_socket)
            else:  # HTTP协议处理
                return self._handle_http_protocol(client_socket)

        except Exception as e:
            logger.error(f"协议检测异常: {repr(e)}")
            client_socket.close()
            return None

    def _handle_socks5(self, client_socket):
        """处理SOCKS5协议连接，保持与原有返回格式一致"""
        try:
            # 认证协商阶段
            client_socket.recv(2)  # 已经通过peek确认版本
            nmethods = client_socket.recv(1)[0]
            client_socket.recv(nmethods)  # 读取方法列表
            client_socket.sendall(b"\x05\x00")  # 选择无认证

            # 请求解析阶段
            header = client_socket.recv(3)
            while header[0]!=0x05:
                logger.debug("right 1, %s",str(header))
                header=header[1:]+client_socket.recv(1)
            logger.debug("socks5 header: %s",header)
            if len(header) != 3 or header[0] != 0x05:
                raise ValueError("Invalid SOCKS5 header")

            _, cmd, _ = header
            
            if cmd not in {0x01, 0x05}:  # 只支持CONNECT和UDP（over TCP）命令
                client_socket.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                raise ValueError(f"Not supported socks command, {cmd}")

            # 目标地址解析（复用原有DNS逻辑）
            server_name, server_port = utils.parse_socks5_address(client_socket)
            
            logger.info("%s:%d",server_name,server_port)

            # 建立连接（完全复用原有逻辑）
            try:
                if cmd==0x01:
                    remote_obj = remote.Remote(server_name, server_port, 6)
                elif cmd==0x05:
                    remote_obj = remote.Remote(server_name, server_port, 17)
                    
                client_socket.sendall(
                    b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client_socket.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                return server_name if utils.is_ip_address(server_name) else None

        except Exception as e:
            logger.info(f"SOCKS5处理错误: {repr(e)}")
            client_socket.close()
            return None

    def _handle_http_protocol(self, client_socket):
        """原有HTTP处理逻辑完整保留"""
        data = client_socket.recv(16384)

        # 原有CONNECT处理
        if data.startswith(b"CONNECT "):
            server_name, server_port = self.extract_servername_and_port(data)
            logger.info(f"CONNECT {server_name}:{server_port}")

            try:
                remote_obj = remote.Remote(server_name, server_port)
                client_socket.sendall(
                    b"HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nProxy-agent : MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return server_name if utils.is_ip_address(server_name) else None

        # 原有PAC文件处理
        elif b"/proxy.pac" in data.splitlines()[0]:
            response = load_pac()
            client_socket.sendall(response.encode())
            client_socket.close()
            return None

        # 原有HTTP重定向逻辑
        elif data.startswith((b'GET ', b'PUT ', b'DELETE ', b'POST ', b'HEAD ', b'OPTIONS ')):
            response = utils.generate_302(data,"github.com")
            client_socket.sendall(response.encode(encoding="UTF-8"))
            client_socket.close()
            return None

        # 原有错误处理
        else:
            logger.info(f"未知请求: {data[:10]}")
            client_socket.sendall(
                b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
            )
            client_socket.close()
            return None  

    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock = self.handle_client_request(client_sock)
        if backend_sock == None:
            client_sock.close()
            return
            
        global ThreadtoWork
        while ThreadtoWork:
            try:
                if first_flag is True:
                    first_flag = False

                    time.sleep(
                        0.1
                    )  # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)

                    try:
                        extractedsni = utils.extract_sni(data)
                        if backend_sock.domain=="127.0.0.114" or backend_sock.domain=="::114" or (config["BySNIfirst"] and str(extractedsni,encoding="ASCII") != backend_sock.domain):
                            port, protocol=backend_sock.port,backend_sock.protocol
                            logger.info(f"replace backendsock: {extractedsni} {port} {protocol}")
                            new_backend_sock=remote.Remote(str(extractedsni,encoding="ASCII"),port,protocol)
                            backend_sock=new_backend_sock
                    except: 
                        pass

                    backend_sock.client_sock = client_sock

                    try:
                        backend_sock.connect()
                    except:
                        raise Exception("backend connect fail")
                    

                    if backend_sock.policy.get("safety_check") is True and data.startswith((b'GET ', b'PUT ', b'DELETE ', b'POST ', b'HEAD ', b'OPTIONS ')):
                        logger.warning("HTTP protocol detected, will redirect to https")
                        # 如果是http协议，重定向到https，要从data中提取url
                        response = utils.generate_302(data,extractedsni)
                        client_sock.sendall(response.encode())
                        client_sock.close()
                        backend_sock.close()
                        
                    if data:
                        thread_down = threading.Thread(
                            target=self.my_downstream,
                            args=(backend_sock, client_sock),
                        )
                        thread_down.daemon = True
                        thread_down.start()
                        # backend_sock.sendall(data)

                    try:
                        backend_sock.sni = extractedsni
                        if str(backend_sock.sni)!=str(backend_sock.domain):
                            backend_sock.policy = {**backend_sock.policy, **match_domain(str(backend_sock.sni))}
                    except:
                        backend_sock.send(data)
                        continue

                    if backend_sock.policy.get("safety_check") is True:
                        try:
                            can_pass=utils.detect_tls_version_by_keyshare(data)
                        except:
                            pass
                        if can_pass != 1:
                            logger.warning("Not a TLS 1.3 connection and will close")
                            try:
                                client_sock.send(utils.generate_tls_alert(data))
                            except:
                                pass
                            backend_sock.close()
                            client_sock.close()
                            raise ValueError("Not a TLS 1.3 connection")

                    if data:
                        mode = backend_sock.policy.get('mode')
                        if mode == "TLSfrag":
                            fragment.send_fraggmed_tls_data(backend_sock, data)
                        elif mode == "FAKEdesync":
                            fake_desync.send_data_with_fake(backend_sock,data)
                        elif mode == "DIRECT":
                            backend_sock.send(data)
                        elif mode == "GFWlike":
                            backend_sock.close()
                            client_sock.close()
                            return False

                    else:
                        raise Exception("cli syn close")

                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.send(data)
                    else:
                        raise Exception("cli pipe close")

            except Exception as e:
                # import traceback
                # traceback.print_exc()
                logger.info(f"upstream : {repr(e)} from {backend_sock.domain}")
                time.sleep(2)  # wait two second for another thread to flush
                client_sock.close()
                backend_sock.close()
                return False

        client_sock.close()
        backend_sock.close()

    def my_downstream(self, backend_sock: remote.Remote, client_sock: socket.socket):

        first_flag = True
        global ThreadtoWork
        while ThreadtoWork:
            try:
                if first_flag is True:
                    first_flag = False
                    data = backend_sock.recv(16384)          
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception("backend pipe close at first")

                else:
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception("backend pipe close")

            except Exception as e:
                # import traceback
                # traceback.print_exc()
                logger.info(f"downstream : {repr(e)} from {backend_sock.domain}")
                time.sleep(2)  # wait two second for another thread to flush
                backend_sock.close()
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
                for _ in range(6):
                    idx = host_and_port.find(":", idx + 1)
                host = host_and_port[:idx]
                port = host_and_port[idx + 1 :]
        return (host, int(port))


# http114=b""


serverHandle = None

def start_server(block=True):
    try:
      generate_pac()
    except:
      pass
    
    global serverHandle
    logger.info(f"Now listening at: 127.0.0.1:{config['port']}")
    serverHandle = ThreadedServer("", config["port"]).listen(block)

def stop_server(wait_for_stop=True):
    global ThreadtoWork, proxy_thread
    ThreadtoWork = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", config["port"]))
    sock.close()
    if wait_for_stop:
        while proxy_thread.is_alive():
            pass
        logger.info("Server stopped")


dataPath = Path.cwd()
ThreadtoWork = True

if __name__ == "__main__":
    start_server()
