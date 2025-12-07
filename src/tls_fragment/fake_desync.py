import socket
from .utils import set_ttl,find_second_last_dot
from .log import logger
from . import remote
from .config import config
import time
import threading

# 实现lock，使得最多同时运行k个
transmitfile_semaphore = threading.Semaphore(config["TransmitFile_Limit"])

logger = logger.getChild("fake_desync")

try:
    import platform
    system = platform.system()
    if system == "Windows":

        import ctypes
        from ctypes import wintypes

        # 加载 mswsock.dll 库
        mswsock = ctypes.WinDLL("mswsock")
        # 加载 ws2_32.dll 库
        ws2_32 = ctypes.windll.ws2_32
        # 加载 kernel32.dll 库
        kernel32 = ctypes.windll.kernel32
        msvcrt = ctypes.cdll.msvcrt

        class _DUMMYSTRUCTNAME(ctypes.Structure):
            _fields_ = [
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
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
                ("hEvent", ctypes.c_void_p),
            ]

        # import pywintypes
        mswsock.TransmitFile.argtypes = [
            wintypes.HANDLE,  # 套接字句柄
            wintypes.HANDLE,  # 文件句柄
            wintypes.DWORD,  # 要发送的字节数
            wintypes.DWORD,  # 每次发送的字节数
            ctypes.POINTER(OVERLAPPED),  # 重叠结构指针
            ctypes.POINTER(ctypes.c_void_p),  # 传输缓冲区指针
            wintypes.DWORD,  # 保留参数
        ]
        # 定义 TransmitFile 函数的返回值类型
        mswsock.TransmitFile.restype = wintypes.BOOL
        # ws2_32.WSASocketW.argtypes = [
        #     wintypes.INT, wintypes.INT, wintypes.INT,
        #     wintypes.DWORD,wintypes.DWORD, wintypes.DWORD
        # ]
        # ws2_32.WSASocketW.restype = ctypes.c_uint

        kernel32.CreateFileA.argtypes = [
            wintypes.LPCSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        kernel32.CreateFileA.restype = wintypes.HANDLE
        kernel32.WriteFile.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        kernel32.WriteFile.restype = wintypes.BOOL
        kernel32.SetFilePointer.argtypes = [
            wintypes.HANDLE,
            ctypes.c_long,
            wintypes.LONG,
            wintypes.DWORD,
        ]
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
    elif system in {"Linux", "Darwin", "Android"}:
        import ctypes

        # 加载 libc 库

        try:
            libc = ctypes.CDLL("libc.so.6")
        except:
            libc = ctypes.CDLL("/system/lib64/libc.so")

        class iovec(ctypes.Structure):
            _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

        # 定义 splice 函数的参数类型和返回类型
        libc.splice.argtypes = [
            ctypes.c_int,  # int fd_in
            ctypes.c_longlong,  # loff_t *off_in
            ctypes.c_int,  # int fd_out
            ctypes.c_longlong,  # loff_t *off_out
            ctypes.c_size_t,  # size_t len
            ctypes.c_uint,  # unsigned int flags
        ]
        libc.splice.restype = ctypes.c_ssize_t

        # 定义 vmsplice 函数的参数类型和返回类型
        libc.vmsplice.argtypes = [
            ctypes.c_int,  # int fd
            ctypes.POINTER(iovec),  # struct iovec *iov
            ctypes.c_size_t,  # size_t nr_segs
            ctypes.c_uint,  # unsigned int flags
        ]
        libc.vmsplice.restype = ctypes.c_ssize_t

        libc.mmap.argtypes = [
            ctypes.c_void_p,  # void *addr
            ctypes.c_size_t,  # size_t length
            ctypes.c_int,  # int prot
            ctypes.c_int,  # int flags
            ctypes.c_int,  # int fd
            ctypes.c_size_t,  # off_t offset
        ]
        libc.mmap.restype = ctypes.c_void_p

        libc.memcpy.argtypes = [
            ctypes.c_void_p,  # void *dest
            ctypes.c_void_p,  # const void *src
            ctypes.c_size_t,  # size_t n
        ]
        libc.memcpy.restype = ctypes.c_void_p
        libc.close.argtypes = [ctypes.c_int]
        libc.close.restype = ctypes.c_int

        libc.munmap.argtypes = [
            ctypes.c_void_p,  # void *addr
            ctypes.c_size_t,  # size_t length
        ]
        libc.munmap.restype = ctypes.c_int

        libc.pipe.argtypes = [ctypes.POINTER(ctypes.c_int)]
        libc.pipe.restype = ctypes.c_int

        pass
except Exception as e:
    logger.warning(repr(e))


def send_fake_data(
    data_len, fake_data, fake_ttl, real_data, default_ttl, sock, FAKE_sleep
):
    import platform
    system = platform.system()
    logger.info(system)
    if system == "Windows":
        logger.warning(
            "Desync on Windows may cause Error! Make sure other programs are not using the TransmitFile. "
        )
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
        import tempfile, uuid

        file_path = f"{tempfile.gettempdir()}\\{uuid.uuid4()}.txt"
        try:
            sock_file_descriptor = sock.fileno()
            logger.info("sock file discriptor: %s", sock_file_descriptor)
            file_handle = kernel32.CreateFileA(
                bytes(file_path, encoding="utf-8"),
                wintypes.DWORD(0x40000000 | 0x80000000),  # GENERIC_READ | GENERIC_WRITE
                wintypes.DWORD(
                    0x00000001 | 0x00000002
                ),  # FILE_SHARE_READ | FILE_SHARE_WRITE
                None,
                wintypes.DWORD(2),  # CREATE_ALWAYS
                # 0,
                0x00000100,  # FILE_FLAG_DELETE_ON_CLOSE
                None,
            )

            if file_handle == -1:
                raise Exception(
                    "Create file failed, Error code:", kernel32.GetLastError()
                )
            logger.info(f"Create file success {file_handle}")
            try:
                ov = OVERLAPPED()
                ov.hEvent = kernel32.CreateEventA(None, True, False, None)
                if ov.hEvent <= 0:
                    raise Exception(
                        "Failed to create event. Error code:", kernel32.GetLastError()
                    )
                logger.info(f"Create event success {ov.hEvent}")

                kernel32.SetFilePointer(file_handle, 0, 0, 0)
                kernel32.WriteFile(
                    file_handle,
                    fake_data,
                    data_len,
                    ctypes.byref(wintypes.DWORD(0)),
                    None,
                )
                kernel32.SetEndOfFile(file_handle)
                set_ttl(sock, fake_ttl)
                kernel32.SetFilePointer(file_handle, 0, 0, 0)

                logger.debug(f"{fake_data} {real_data} {data_len}")

                # 调用 TransmitFile 函数
                with transmitfile_semaphore:
                    result = mswsock.TransmitFile(
                        sock_file_descriptor,
                        file_handle,
                        wintypes.DWORD(data_len),
                        wintypes.DWORD(data_len),
                        ov,
                        None,
                        32 | 4,  # TF_USE_KERNEL_APC | TF_WRITE_BEHIND
                    )

                    if FAKE_sleep < 0.1:
                        logger.warning("Too short sleep time on Windows, set to 0.1")
                        FAKE_sleep = 0.1

                    logger.info("sleep for: %f", FAKE_sleep)
                    time.sleep(FAKE_sleep)
                    kernel32.SetFilePointer(file_handle, 0, 0, 0)
                    kernel32.WriteFile(
                        file_handle,
                        real_data,
                        data_len,
                        ctypes.byref(wintypes.DWORD(0)),
                        None,
                    )
                    kernel32.SetEndOfFile(file_handle)
                    kernel32.SetFilePointer(file_handle, 0, 0, 0)
                    set_ttl(sock, default_ttl)

                    val = kernel32.WaitForSingleObject(ov.hEvent, wintypes.DWORD(5000))

                if val == 0:
                    logger.info(f"TransmitFile call was successful. {result}")
                else:
                    raise Exception(
                        "TransmitFile call failed (on waiting for event). Error code:",
                        kernel32.GetLastError(),
                        ws2_32.WSAGetLastError(),
                    )
                    
                return True
            except:
                raise Exception(
                    "TransmitFile call failed. Error code:", kernel32.GetLastError()
                )
            finally:
                kernel32.CloseHandle(file_handle)
                kernel32.CloseHandle(ov.hEvent)
                import os
                os.remove(file_path)
        except Exception as e:
            raise e
    elif system in {"Linux", "Darwin", "Android"}:
        try:
            sock_file_descriptor = sock.fileno()
            logger.info(f"sock file discriptor: {sock_file_descriptor}")
            fds = (ctypes.c_int * 2)()
            if libc.pipe(fds) < 0:
                raise Exception("pipe creation failed")
            logger.info("pipe creation success %d %d", fds[0], fds[1])
            p = libc.mmap(
                0, ((data_len - 1) // 4 + 1) * 4, 0x1 | 0x2, 0x2 | 0x20, 0, 0
            )  # PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS
            if p == ctypes.c_void_p(-1):
                raise Exception("mmap failed")
            logger.info("mmap success %s", p)
            libc.memcpy(p, fake_data, data_len)
            set_ttl(sock, fake_ttl)
            vec = iovec(p, data_len)
            len = libc.vmsplice(fds[1], ctypes.byref(vec), 1, 2)  # SPLICE_F_GIFT
            if len < 0:
                raise Exception("vmsplice failed")
            logger.info("vmsplice success %d", len)
            len = libc.splice(fds[0], 0, sock_file_descriptor, 0, data_len, 0)
            if len < 0:
                raise Exception("splice failed")
            logger.info("splice success %d", len)
            logger.info(f"sleep for: {FAKE_sleep}")
            time.sleep(FAKE_sleep)
            libc.memcpy(p, real_data, data_len)
            set_ttl(sock, default_ttl)
            return True
        except Exception as e:
            raise e
        finally:
            libc.munmap(p, ((data_len - 1) // 4 + 1) * 4)
            libc.close(fds[0])
            libc.close(fds[1])
    else:
        raise Exception("unknown os")


def send_data_with_fake(sock: remote.Remote, data):
    logger.info("To send: %d Bytes. ", len(data))  # check os
    # if windows, use TransmitFile
    default_ttl = sock.sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
    try:
        fake_data = sock.policy.get("fake_packet")
        fake_ttl = int(sock.policy.get("fake_ttl"))
    except:
        raise Exception("FAKE_packet or FAKE_ttl not set in settings.json")

    data_len = len(fake_data)
    FAKE_sleep = sock.policy.get("fake_sleep")
    if send_fake_data(
        data_len,
        fake_data,
        fake_ttl,
        data[0:data_len],
        default_ttl,
        sock.sock,
        FAKE_sleep,
    ):
        logger.info("Fake data sent.")
    else:
        raise Exception("Failed to send fake data.")

    data = data[data_len:]
    sni=sock.sni
    if sni==None:
        sock.send(data)
        return
    
    position = data.find(sni)
    logger.debug(f"{sni} {position}")
    if position == -1:
        sock.send(data)
        return
    sni_len = len(sni)

    sock.send(data[0:position])
    data=data[position:]

    if sock.policy.get("len_tcp_sni") >= sni_len:
        sock.policy["len_tcp_sni"]=sni_len/2
        logger.info("len_tcp_sni too big, set to %d",sock.policy.get("len_tcp_sni"))
    
    sld=find_second_last_dot(sni)
    
    if sock.policy.get("len_tcp_sni")<=sld:
        sock.policy["len_tcp_sni"]=sld+2
        logger.info("len_tcp_sni too small, set to %d",sock.policy.get("len_tcp_sni"))

    if send_fake_data(
        sock.policy.get("len_tcp_sni"),
        fake_data,
        fake_ttl,
        sni[0:sock.policy.get("len_tcp_sni")],
        default_ttl,
        sock.sock,
        FAKE_sleep,
    ):
        logger.info("Fake sni sent.")
    else:
        raise Exception("Failed to send fake SNI.")

    data=data[sock.policy.get("len_tcp_sni"):]
    
    sock.send(data)
