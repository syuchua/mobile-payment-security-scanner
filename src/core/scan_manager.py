# -*- coding: utf-8 -*-
from typing import List
import logging
from src.core.vulnerability_scanner import VulnerabilityResult
from src.vulnerabilities.sql_injection import SQLInjectionScanner
from src.vulnerabilities.xss import XSSScanner
from src.vulnerabilities.sensitive_data import SensitiveDataScanner
from src.vulnerabilities.authentication import AuthenticationScanner
from src.vulnerabilities.api_security import APISecurityScanner
from src.vulnerabilities.csrf import CSRFScanner  # 新增CSRF扫描器


class ScanManager:
    """扫描管理器，负责协调所有安全扫描器的运行"""

    def __init__(self, config_manager):
        """初始化扫描管理器

        Args:
            config_manager: 配置管理器实例
        """
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.target_url = config_manager.get_target_url()

        # 设置拦截器
        if 'general' in config_manager.config and 'interceptor' in config_manager.config['general']:
            self.interceptor = config_manager.config['general']['interceptor']
        else:
            from src.core.request_interceptor import RequestInterceptor
            self.interceptor = RequestInterceptor(self.target_url)

        # 初始化所有扫描器
        self.scanners = [
            SQLInjectionScanner(self.interceptor, self.config_manager),
            XSSScanner(self.interceptor, self.config_manager),
            SensitiveDataScanner(self.interceptor, self.config_manager),
            AuthenticationScanner(self.interceptor, self.config_manager),
            APISecurityScanner(self.interceptor, self.config_manager),
            CSRFScanner(self.interceptor, self.config_manager)  # 添加CSRF扫描器
        ]

    def run_all_scanners(self) -> List[VulnerabilityResult]:
        """运行所有扫描器

        Returns:
            List[VulnerabilityResult]: 所有发现的漏洞
        """
        all_vulnerabilities = []
        completed_scanners = 0

        for scanner in self.scanners:
            scanner_name = scanner._get_scanner_name()
            self.logger.info(f"开始执行{scanner_name}...")

            try:
                vulnerabilities = scanner.scan()
                all_vulnerabilities.extend(vulnerabilities)
                completed_scanners += 1
                self.logger.info(
                    f"[{completed_scanners}/{len(self.scanners)}] {scanner_name}完成，发现 {len(vulnerabilities)} 个漏洞")
            except Exception as e:
                self.logger.error(f"运行 {scanner_name} 时出错: {e}", exc_info=True)

        return all_vulnerabilities