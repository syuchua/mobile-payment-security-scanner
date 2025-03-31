# -*- coding: utf-8 -*-
from typing import List, Dict, Any
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.scanner_strategy import ScannerStrategy


class SQLInjectionScanner(ScannerStrategy):
    """SQL注入漏洞扫描器"""

    def _get_scanner_name(self) -> str:
        return "SQL注入漏洞扫描"

    def scan(self) -> List[VulnerabilityResult]:
        """执行SQL注入漏洞扫描

        Returns:
            List[VulnerabilityResult]: 发现的SQL注入漏洞列表
        """
        vulnerabilities = []

        # 测试常见的URL参数
        test_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users",
            "1' OR '1'='1' --",
            "' UNION SELECT username, password FROM users --"
        ]

        endpoints = ['/api/users', '/api/products', '/search']

        for endpoint in endpoints:
            for payload in test_payloads:
                try:
                    # 发送测试请求
                    response = self.interceptor.intercept_request(
                        'GET',
                        f"{endpoint}?id={payload}",
                        headers={'Content-Type': 'application/json'}
                    )

                    # 分析响应，检查SQL错误模式
                    if self._check_for_sql_errors(response.text):
                        vulnerabilities.append(
                            VulnerabilityResult(
                                vulnerability_type="SQL注入漏洞",
                                severity="高",
                                description="发现可能的SQL注入点",
                                affected_endpoint=endpoint,
                                details={
                                    "参数": "id",
                                    "测试载荷": payload,
                                    "响应状态码": response.status_code,
                                    "错误模式": self._extract_error_pattern(response.text)
                                },
                                recommendations=[
                                    "使用参数化查询而不是字符串拼接",
                                    "实施输入验证和过滤",
                                    "应用最小权限原则配置数据库用户"
                                ]
                            )
                        )
                except Exception as e:
                    # 记录异常但继续扫描
                    pass

        return vulnerabilities

    def _check_for_sql_errors(self, response_text: str) -> bool:
        """检查响应中是否包含SQL错误的特征"""
        error_patterns = [
            "SQL syntax", "mysql_fetch_array", "ORA-",
            "SQL Server", "syntax error", "unclosed quotation mark"
        ]

        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                return True

        return False

    def _extract_error_pattern(self, response_text: str) -> str:
        """提取响应中的错误模式"""
        # 简化实现，实际中可能需要更复杂的模式匹配
        error_patterns = [
            "SQL syntax", "mysql_fetch_array", "ORA-",
            "SQL Server", "syntax error", "unclosed quotation mark"
        ]

        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                return pattern

        return "未知错误"