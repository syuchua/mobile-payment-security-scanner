# -*- coding: utf-8 -*-
# src/core/scanner_factory.py
from typing import Dict, Type
from src.core.scanner_strategy import ScannerStrategy
from src.core.network_interceptor import NetworkInterceptor
from src.vulnerabilities.injection import SQLInjectionScanner
from src.vulnerabilities.xss import XSSScanner
from src.vulnerabilities.sensitive_data import SensitiveDataScanner
from src.vulnerabilities.authentication import AuthenticationScanner
from src.vulnerabilities.api_security import APISecurityScanner

class ScannerFactory:
    """扫描器工厂类"""

    _scanner_registry: Dict[str, Type[ScannerStrategy]] = {
        "sql_injection": SQLInjectionScanner,
        "xss": XSSScanner,
        "sensitive_data": SensitiveDataScanner,
        "authentication": AuthenticationScanner,
        # 注册新的扫描器
        "api_security": APISecurityScanner,
    }

    @classmethod
    def register_scanner(cls, scanner_type: str, scanner_class: Type[ScannerStrategy]) -> None:
        """注册新的扫描器类型

        Args:
            scanner_type: 扫描器类型标识
            scanner_class: 扫描器类
        """
        cls._scanner_registry[scanner_type] = scanner_class

    @classmethod
    def create_scanner(cls, scanner_type: str, interceptor: NetworkInterceptor) -> ScannerStrategy:
        """创建指定类型的扫描器实例

        Args:
            scanner_type: 扫描器类型标识
            interceptor: 网络请求拦截器

        Returns:
            ScannerStrategy: 扫描器实例

        Raises:
            ValueError: 如果指定的扫描器类型不存在
        """
        if scanner_type not in cls._scanner_registry:
            raise ValueError(f"未知的扫描器类型: {scanner_type}")

        scanner_class = cls._scanner_registry[scanner_type]
        return scanner_class(interceptor)

    @classmethod
    def get_all_scanner_types(cls) -> list:
        """获取所有已注册的扫描器类型

        Returns:
            list: 所有已注册的扫描器类型
        """
        return list(cls._scanner_registry.keys())