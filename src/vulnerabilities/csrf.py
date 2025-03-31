# -*- coding: utf-8 -*-
from typing import List
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.scanner_strategy import ScannerStrategy


class CSRFScanner(ScannerStrategy):
    """CSRF漏洞扫描器"""

    def _get_scanner_name(self) -> str:
        return "CSRF漏洞扫描"

    def scan(self) -> List[VulnerabilityResult]:
        """执行CSRF漏洞扫描

        Returns:
            List[VulnerabilityResult]: 发现的CSRF漏洞列表
        """
        vulnerabilities = []

        # 检查标准版中的CSRF漏洞端点
        endpoints = [
            '/api/update_profile',
            '/profile/update',
            '/settings/save'
        ]

        for endpoint in endpoints:
            try:
                # 尝试没有CSRF令牌的请求
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Bearer fake_token_for_testing"
                }

                response = self.interceptor.intercept_request(
                    'POST',
                    endpoint,
                    data={"name": "csrf_test_user"},
                    headers=headers
                )

                # 检查是否存在CSRF保护
                if self._check_for_csrf_vulnerability(response):
                    vulnerabilities.append(
                        VulnerabilityResult(
                            vulnerability_type="跨站请求伪造(CSRF)",
                            severity="中",
                            description="缺少CSRF保护",
                            affected_endpoint=endpoint,
                            details={
                                "问题": "表单提交未包含CSRF令牌验证",
                                "风险": "攻击者可以诱导用户执行未授权的操作"
                            },
                            recommendations=[
                                "实现CSRF令牌验证",
                                "验证请求来源(Origin/Referer)",
                                "使用SameSite Cookie属性"
                            ]
                        )
                    )
            except Exception as e:
                self.logger.error(f"扫描CSRF时出错 (端点: {endpoint}): {e}")

        return vulnerabilities

    def _check_for_csrf_vulnerability(self, response) -> bool:
        """检查是否存在CSRF漏洞"""
        # 响应状态码2xx或3xx可能表示接受了请求
        if 200 <= response.status_code < 400:
            return True

        # 检查401响应是否只因令牌无效而非CSRF保护
        if response.status_code == 401:
            return True

        return False