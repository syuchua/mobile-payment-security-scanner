# -*- coding: utf-8 -*-
from typing import List
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

        # SQL注入测试载荷
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "admin' --",
            "1; DROP TABLE users",
            "1' UNION SELECT 1,username,password FROM users --"
        ]

        # 测试不同的端点
        endpoints = [
            '/api/login',
            '/api/authenticate',
            '/auth/token',
            '/api/feedback'
        ]

        for endpoint in endpoints:
            for payload in payloads:
                try:
                    if endpoint in ['/api/login', '/api/authenticate', '/auth/token']:
                        # 认证端点通常使用POST请求
                        response = self.interceptor.intercept_request(
                            'POST',
                            endpoint,
                            json={"username": payload, "password": "test"}
                        )
                    else:
                        # 其他端点可能使用GET参数
                        response = self.interceptor.intercept_request(
                            'GET',
                            f"{endpoint}?id={payload}"
                        )

                    # 分析响应中的SQL注入迹象
                    if self._check_for_sql_injection(response):
                        vulnerabilities.append(
                            VulnerabilityResult(
                                vulnerability_type="SQL注入",
                                severity="高",
                                description="发现SQL注入漏洞",
                                affected_endpoint=endpoint,
                                details={
                                    "问题": "未过滤的用户输入直接用于SQL查询",
                                    "风险": "攻击者可以执行任意SQL命令，访问、修改或删除数据库内容",
                                    "载荷": payload
                                },
                                recommendations=[
                                    "使用参数化查询",
                                    "实施输入验证",
                                    "限制数据库用户权限",
                                    "使用ORM框架"
                                ]
                            )
                        )
                        break  # 一旦发现漏洞，不需要继续测试此端点
                except Exception as e:
                    self.logger.error(f"扫描SQL注入时出错 (端点: {endpoint}): {e}")

        return vulnerabilities

    def _check_for_sql_injection(self, response) -> bool:
        """分析响应中是否存在SQL注入迹象"""
        # 检查常见的SQL错误消息
        error_patterns = [
            "SQL syntax",
            "mysql_fetch_array",
            "ORA-01756",
            "SQLSTATE",
            "MySQL Error",
            "Microsoft SQL",
            "PostgreSQL ERROR"
        ]

        for pattern in error_patterns:
            if pattern.lower() in response.text.lower():
                return True

        # 检查响应状态码与内容长度异常
        if response.status_code == 200 and "admin" in response.text.lower():
            return True

        return False