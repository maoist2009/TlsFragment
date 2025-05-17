# service/main.py
from kivy.logger import Logger
import os
import threading
from src.tls_fragment.cli import start_server, stop_server

"""启动代理服务器并保持服务运行"""
Logger.info("Service: Starting proxy server")

try:
    # 启动代理服务器（非阻塞模式）
    # 不再传递config参数
    Logger.info("Service: Proxy server started successfully")
    start_server(block=True)
    
    # # 保持主线程运行，防止服务被系统终止
    # Clock.schedule_interval(lambda dt: None, 1)
    
except Exception as e:
    Logger.error(f"Service: Error starting server: {str(e)}")

