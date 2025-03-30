import requests
from typing import Dict, Any, Optional


class RequestInterceptor:
    """请求拦截器，用于统一处理HTTP请求"""

    def __init__(self, base_url: str):
        """初始化请求拦截器

        Args:
            base_url: 目标系统的基础URL
        """
        self.base_url = base_url
        self.session = requests.Session()

    def intercept_request(self, method: str, endpoint: str,
                          data: Optional[Dict[str, Any]] = None,
                          json: Optional[Dict[str, Any]] = None,
                          headers: Optional[Dict[str, str]] = None,
                          params: Optional[Dict[str, Any]] = None) -> requests.Response:
        """拦截并发送HTTP请求

        Args:
            method: HTTP方法 (GET, POST等)
            endpoint: 请求端点（相对路径）
            data: 表单数据
            json: JSON数据
            headers: HTTP头
            params: URL查询参数

        Returns:
            requests.Response: 请求响应
        """
        url = f"{self.base_url}{endpoint}" if not endpoint.startswith(self.base_url) else endpoint

        return self.session.request(
            method=method,
            url=url,
            data=data,
            json=json,
            headers=headers,
            params=params,
            timeout=10,
            allow_redirects=True,
            verify=False  # 允许自签名证书，仅用于测试
        )