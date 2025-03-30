# src/core/mock_system.py
import logging
import sys
import socket
from src.core.mock_interceptor import MockNetworkInterceptor


class MockSystem:
    """全局模拟系统，拦截所有网络请求"""

    @staticmethod
    def enable_global_mock_mode():
        """启用全局模拟模式，拦截所有网络请求"""
        logger = logging.getLogger("MockSystem")
        logger.info("正在启用全局模拟模式...")

        # 创建模拟拦截器
        mock_interceptor = MockNetworkInterceptor()

        # 拦截所有socket连接
        original_socket_connect = socket.socket.connect

        def mock_connect(self, address):
            host, port = address if isinstance(address, tuple) else (address, 0)
            logger.info(f"已拦截socket连接: {host}:{port}")
            if isinstance(host, str) and ("example-payment-system.com" in host):
                raise ConnectionRefusedError(f"模拟模式下不允许连接到: {host}:{port}")
            return original_socket_connect(self, address)

        # 替换socket连接方法
        socket.socket.connect = mock_connect

        # 替换requests库
        try:
            import requests

            # 保存原始请求函数
            original_requests_get = requests.get
            original_requests_post = requests.post
            original_requests_put = requests.put
            original_requests_delete = requests.delete

            # 替换requests库方法
            requests.get = mock_interceptor.get
            requests.post = mock_interceptor.post
            requests.put = mock_interceptor.put
            requests.delete = mock_interceptor.delete

            logger.info("已替换requests库方法")
        except ImportError:
            logger.warning("未找到requests库，跳过替换")

        logger.info("全局模拟模式已启用，所有相关网络请求将被拦截")

        return mock_interceptor