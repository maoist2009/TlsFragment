# service/main.py
from kivy.logger import Logger
from kivy.clock import Clock
import os
import threading
# 修正导入路径，src 在父目录
from sys import path
path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from src.tls_fragment.cli import start_server, stop_server

# 导入Android Java类
from jnius import autoclass, PythonJavaClass, java_method

# 获取PythonService类
PythonService = autoclass('org.kivy.android.PythonService')

class ServiceApp:
    def __init__(self):
        self.server_running = False
        Logger.info("Service: Initializing proxy service")
        
    def start(self):
        """启动代理服务器并保持服务运行"""
        Logger.info("Service: Starting proxy server")
        self.server_running = True
        
        try:
            # 启动代理服务器（非阻塞模式）
            # 不再传递config参数
            start_server(block=False)
            Logger.info("Service: Proxy server started successfully")
            
            # 保持主线程运行，防止服务被系统终止
            Clock.schedule_interval(lambda dt: None, 1)
            
        except Exception as e:
            Logger.error(f"Service: Error starting server: {str(e)}")
            self.server_running = False
    
    def stop(self):
        """停止代理服务器和服务"""
        Logger.info("Service: Stopping proxy server")
        if self.server_running:
            try:
                stop_server(wait_for_stop=True)
                self.server_running = False
                Logger.info("Service: Proxy server stopped")
            except Exception as e:
                Logger.error(f"Service: Error stopping server: {str(e)}")
        
        # 停止服务
        PythonService.mService.stopSelf()
        Logger.info("Service: Service stopped")

# 创建服务实例
service = ServiceApp()

# 定义服务入口函数
def main():
    Logger.info("Service: Starting proxy service main function")
    service.start()