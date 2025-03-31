# -*- coding: utf-8 -*-
# src/core/network_interceptor.py
import requests
from typing import Dict, Any, Optional


class NetworkInterceptor:
    """网络请求拦截器"""

    def __init__(self, target_url: str, timeout: int = 10, user_agent: str = 'SecurityScanner/1.0'):
        """初始化网络拦截器

        Args:
            target_url: 目标URL
            timeout: 请求超时时间(秒)
            user_agent: 用户代理字符串
        """
        self.target_url = target_url
        self.timeout = timeout
        self.headers = {
            'User-Agent': user_agent
        }

    def intercept_request(self, method: str, endpoint: str,
                          params: Optional[Dict[str, Any]] = None,
                          json: Optional[Dict[str, Any]] = None,
                          data: Optional[Dict[str, Any]] = None,
                          headers: Optional[Dict[str, Any]] = None) -> requests.Response:
        """拦截并发送HTTP请求

        Args:
            method: HTTP方法 (GET, POST, PUT, DELETE等)
            endpoint: API端点
            params: URL参数
            json: JSON请求体
            data: 表单数据
            headers: HTTP头部

        Returns:
            requests.Response: HTTP响应
        """
        url = self.target_url.rstrip('/') + '/' + endpoint.lstrip('/')

        # 合并默认头部和传入的头部
        merged_headers = self.headers.copy()
        if headers:
            merged_headers.update(headers)

        return requests.request(
            method=method,
            url=url,
            params=params,
            json=json,
            data=data,
            headers=merged_headers,
            timeout=self.timeout
        )