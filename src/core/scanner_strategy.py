# -*- coding: utf-8 -*-
# src/core/scanner_strategy.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.network_interceptor import NetworkInterceptor
from src.protection.security_monitor import SecurityMonitor

class ScannerStrategy(ABC):
    """扫描器策略接口"""

    def __init__(self, interceptor: NetworkInterceptor, security_monitor: SecurityMonitor = None):
        """初始化扫描器

        Args:
            interceptor: 网络请求拦截器
            security_monitor: 安全监控器
        """
        self.interceptor = interceptor
        self.name = self._get_scanner_name()
        self.config = {}
        self.security_monitor = security_monitor or SecurityMonitor()

    def log_vulnerability(self, vulnerability_type: str, details: Dict[str, Any],
                          severity: str = "error") -> None:
        """记录发现的漏洞

        Args:
            vulnerability_type: 漏洞类型
            details: 漏洞详情
            severity: 严重程度
        """
        if self.security_monitor:
            self.security_monitor.log_vulnerability_detection(
                vulnerability_type=vulnerability_type,
                details=details,
                severity=severity
            )

    def configure(self, config: Dict[str, Any]) -> None:
        """配置扫描器参数

        Args:
            config: 扫描器配置
        """
        self.config = config

    @abstractmethod
    def scan(self) -> List[VulnerabilityResult]:
        """执行扫描并返回发现的漏洞

        Returns:
            List[VulnerabilityResult]: 发现的漏洞列表
        """
        pass

    @abstractmethod
    def _get_scanner_name(self) -> str:
        """获取扫描器名称

        Returns:
            str: 扫描器名称
        """
        pass