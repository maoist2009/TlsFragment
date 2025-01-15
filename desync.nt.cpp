#include <winsock2.h>
#include <mswsock.h>
#include <Windows.h>
#define EXPORT __declspec(dllexport)


int send_fake(SOCKET sock,int fake_ttl,int default_ttl,int plen,char* fake_buffer,char* real_buffer,OVERLAPPED ov)
{
    char path[MAX_PATH], temp[MAX_PATH + 1];
    int ps = GetTempPath(sizeof(temp), temp);
    if (!ps) return -2;
    if (!GetTempFileName(temp, "t", 0, path)) return -3;
//    LOG(LOG_L, "temp file: %s\n", path);
    
    HANDLE hfile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hfile == INVALID_HANDLE_VALUE) return -4;
    ssize_t len = -1;
    
    while (1) {
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) break;
        DWORD wrtcnt = 0;
        if (!WriteFile(hfile, fake_buffer, plen, &wrtcnt, 0)) break;
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) break;
        if (setsockopt(sock,IPPROTO_IP,IP_TTL,(char*)&fake_ttl,sizeof(fake_ttl)) < 0) break;
        if (!TransmitFile(sock, hfile, pos, pos, &ov, 
                NULL, TF_USE_KERNEL_APC | TF_WRITE_BEHIND)) {
            if ((GetLastError() != ERROR_IO_PENDING) 
                        && (WSAGetLastError() != WSA_IO_PENDING)) break;
        }
        //Sleep(3);
        
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) break;
        if (!WriteFile(hfile, buffer, pos, &wrtcnt, 0)) break;
        if (setsockopt(sock,IPPROTO_IP,IP_TTL,(char*)&default_ttl,sizeof(default_ttl)) < 0) break;
        len = pos;
        break;
    }
    if (!CloseHandle(hfile)
            || (ov.hEvent && !CloseHandle(ov.hEvent))) return -1;
    return len;
}
