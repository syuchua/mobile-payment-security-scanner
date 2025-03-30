# src/core/mock_interceptor.py
import logging
from datetime import datetime
import json
from urllib.parse import urlparse


class MockResponse:
    """模拟的HTTP响应类"""

    def __init__(self, status_code=200, content=None, text="", json_data=None, headers=None):
        self.status_code = status_code
        self.content = content or b""
        self.text = text
        self._json = json_data or {}
        self.headers = headers or {}
        self.url = "https://mock-url.example.com"
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._json

    def raise_for_status(self):
        if 400 <= self.status_code < 600:
            raise Exception(f"HTTP Error: {self.status_code}")
        return self


class MockNetworkInterceptor:
    """完全模拟网络请求的拦截器，确保不发送任何实际网络请求"""

    def __init__(self):
        self.logger = logging.getLogger("MockInterceptor")
        self.logger.info("初始化模拟网络拦截器 - 完全模拟模式")

    def intercept_request(self, method, endpoint, **kwargs):
        """
        拦截并模拟网络请求 - 支持相对路径和完整URL

        Args:
            method: HTTP方法 (GET, POST等)
            endpoint: 请求端点或完整URL
            **kwargs: 请求参数

        Returns:
            MockResponse: 模拟的HTTP响应
        """
        self.logger.info(f"模拟请求: {method} {endpoint}")

        # 打印请求信息以便调试
        if 'json' in kwargs:
            self.logger.debug(f"请求数据: {kwargs['json']}")

        # 根据不同端点返回模拟响应
        if '/api/payment' in endpoint:
            return self._mock_payment_response()
        elif '/api/scan' in endpoint:
            return self._mock_scan_response(endpoint)
        elif 'security-rules' in endpoint:
            return self._mock_rules_response()
        else:
            # 默认响应
            return MockResponse(
                status_code=200,
                json_data={"status": "success", "message": f"Mock response for {endpoint}"}
            )

    # 添加一个通用请求方法，会自动调用intercept_request
    def request(self, method, url, **kwargs):
        """通用请求方法，模拟requests.request的行为"""
        return self.intercept_request(method, url, **kwargs)

    # 模拟requests库常用的方法
    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def _mock_payment_response(self):
        """模拟支付API响应"""
        return MockResponse(
            status_code=200,
            json_data={
                "transaction_id": "mock_tx_12345",
                "status": "completed",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": {
                    "processed": True,
                    "fee": "1.50",
                    "provider": "MockPaymentProcessor"
                }
            }
        )

    def _mock_scan_response(self, endpoint):
        """模拟安全扫描API响应"""
        vulnerabilities = [
            {
                "id": "VULN-001",
                "type": "SQL Injection",
                "severity": "High",
                "description": "发现潜在的SQL注入漏洞",
                "location": "/api/users?id=1",
                "details": "用户输入未经过滤直接拼接到SQL查询中"
            },
            {
                "id": "VULN-002",
                "type": "XSS",
                "severity": "Medium",
                "description": "跨站脚本攻击风险",
                "location": "/payment/form",
                "details": "用户输入在页面渲染时未转义"
            }
        ]

        return MockResponse(
            status_code=200,
            json_data={
                "scan_id": "SCAN-MOCK-123",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": "example-payment-system.com",
                "vulnerabilities": vulnerabilities,
                "scan_status": "completed"
            }
        )

    def _mock_rules_response(self):
        """模拟规则更新API响应"""
        return MockResponse(
            status_code=200,
            json_data={
                "status": "up_to_date",
                "version": "2023.10.1",
                "rules_available": ["sql_injection", "xss", "csrf", "sensitive_data"],
                "last_updated": "2023-10-15"
            }
        )