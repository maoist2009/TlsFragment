# service/main.py
from kivy.logger import Logger
from kivy.clock import Clock
import os
import threading
from src.tls_fragment.cli import start_server, stop_server
import plyer

def start():
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

if __name__ == '__main__':
    plyer.notification.notify(title='BackgroundService Test', message="Notification from android service")
    start()