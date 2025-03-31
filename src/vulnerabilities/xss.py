# -*- coding: utf-8 -*-
from typing import List
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.scanner_strategy import ScannerStrategy


class XSSScanner(ScannerStrategy):
    """XSS漏洞扫描器"""

    def _get_scanner_name(self) -> str:
        return "XSS漏洞扫描"

    def scan(self) -> List[VulnerabilityResult]:
        vulnerabilities = []

        # 根据目标端口选择端点
        target_port = self.interceptor.base_url.split(':')[-1].split('/')[0]

        if target_port == '5000':  # 基础版
            endpoints = ['/search', '/feedback', '/profile', '/api/user_data']
        elif target_port == '5001':  # 安全版
            endpoints = ['/secure/search', '/secure/feedback', '/secure/profile', '/api/v2/user_data']
        elif target_port == '5002':  # 增强版
            endpoints = ['/v2/search', '/v2/feedback', '/v2/profile', '/api/v3/user_data']
        else:
            endpoints = ['/search', '/feedback', '/profile', '/api/user_data']

        # 原有的扫描逻辑
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        # 添加标准版特有的端点
        endpoints = ['/search', '/feedback', '/profile', '/api/user_data']

        for endpoint in endpoints:
            for payload in xss_payloads:
                try:
                    # 为不同端点使用对应参数名
                    param_name = 'q' if endpoint != '/api/user_data' else 'username'
                    response = self.interceptor.intercept_request(
                        'GET',
                        headers={'Content-Type': 'application/json'}
                    )

                    # 检查响应中是否包含未经转义的XSS载荷
                    if self._check_for_reflected_xss(response.text, payload):
                        vulnerabilities.append(
                            VulnerabilityResult(
                                vulnerability_type="跨站脚本攻击(XSS)",
                                severity="中",
                                description="发现反射型XSS漏洞",
                                affected_endpoint=endpoint,
                                details={
                                    "问题": "用户输入未经过滤直接输出到页面",
                                    "风险": "攻击者可以注入恶意脚本，窃取用户信息或执行未授权操作",
                                    "载荷": payload
                                },
                                recommendations=[
                                    "对所有用户输入进行HTML编码",
                                    "实现内容安全策略(CSP)",
                                    "使用安全的模板引擎"
                                ]
                            )
                        )
                        break  # 一旦发现漏洞，不需要继续测试此端点
                except Exception as e:
                    self.logger.error(f"扫描XSS时出错 (端点: {endpoint}): {e}")

        return vulnerabilities

    def _check_for_reflected_xss(self, response_text: str, payload: str) -> bool:
        """检查响应中是否包含未转义的XSS载荷"""
        return payload in response_text