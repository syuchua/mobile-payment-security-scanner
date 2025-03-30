# src/vulnerabilities/api_security.py
from typing import List
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.scanner_strategy import ScannerStrategy


class APISecurityScanner(ScannerStrategy):
    """API安全扫描器"""

    def _get_scanner_name(self) -> str:
        return "API安全漏洞扫描"

    def scan(self) -> List[VulnerabilityResult]:
        """执行API安全扫描

        Returns:
            List[VulnerabilityResult]: 发现的API安全漏洞列表
        """
        vulnerabilities = []

        # 获取配置参数
        endpoints = self.config.get("test_endpoints", [])
        methods = self.config.get("check_methods", ["GET", "POST"])
        check_rate_limiting = self.config.get("check_rate_limiting", False)
        check_auth_bypass = self.config.get("check_auth_bypass", False)

        # 扫描逻辑实现...
        # 这里可以使用self.interceptor来发送请求检测漏洞

        return vulnerabilities