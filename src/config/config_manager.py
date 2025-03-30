import os
import yaml
import json
import argparse
from typing import Dict, Any, List, Optional


class ConfigManager:
    """配置管理器，负责加载和管理配置"""

    DEFAULT_CONFIG = {
        "target_url": "https://example.com",
        "parallel_scan": True,
        "scanners": {
            "sql_injection": {
                "enabled": True,
                "timeout": 30,
                "injection_strings": ["'", "\"", "OR 1=1", "' OR '1'='1"]
            },
            "xss": {
                "enabled": True,
                "timeout": 30,
                "test_payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            },
            "sensitive_data": {
                "enabled": True,
                "patterns": ["password", "credit_card", "ssn", "api_key"]
            },
            "authentication": {
                "enabled": True,
                "endpoints": ["/login", "/api/auth"],
                "test_weak_passwords": True
            },
            "api_security": {
                "enabled": True,
                "timeout": 40,
                "test_endpoints": ["/api/v1/users", "/api/v1/payments"],
                "check_methods": ["GET", "POST", "PUT", "DELETE"],
                "check_rate_limiting": True,
                "check_auth_bypass": True
            },
        },
        "reporting": {
            "export_formats": ["pdf", "html"],
            "include_charts": True,
            "report_dir": "reports"
        },
        "general": {
            "request_timeout": 10,
            "max_retries": 3,
            "user_agent": "SecurityScanner/1.0"
        },
        "security_monitoring": {
            "enable_logging": True,
            "log_level": "INFO",
            "ip_threshold": 5,
            "alert_on_suspicious": True,
            "blacklist": [],
            "monitored_events": [
                "authentication_failure",
                "input_validation_failure",
                "vulnerability_detected"
            ]
        },
        "rule_updates": {
            "enable_auto_update": True,
            "update_interval": 86400,  # 每天更新一次
            "update_url": "https://security-rules.example.com/api/latest",
            "rule_base_dir": "rules",
            "alert_on_new_rules": True
        }
    }

    def __init__(self):
        self.config = self.DEFAULT_CONFIG.copy()
        self.args = None
        self.parser = None

    def get_parser(self):
        """获取命令行参数解析器

        Returns:
            argparse.ArgumentParser: 命令行参数解析器
        """
        if self.parser is None:
            self.parser = argparse.ArgumentParser(description='移动支付系统安全漏洞扫描器')

            # 基本配置
            self.parser.add_argument('-u', '--url', dest='target_url',
                                     help='目标系统URL')
            self.parser.add_argument('-c', '--config', dest='config_file',
                                     help='配置文件路径')
            self.parser.add_argument('--no-parallel', dest='parallel_scan',
                                     action='store_false', help='禁用并行扫描')

            # 扫描器启用/禁用
            self.parser.add_argument('--enable-scanner', dest='enable_scanners',
                                     action='append', help='启用特定扫描器')
            self.parser.add_argument('--disable-scanner', dest='disable_scanners',
                                     action='append', help='禁用特定扫描器')

            # 报告选项
            self.parser.add_argument('--report-format', dest='report_formats',
                                     action='append', help='报告格式 (pdf, html)')
            self.parser.add_argument('--report-dir', dest='report_dir',
                                     help='报告输出目录')

            # 超时设置
            self.parser.add_argument('--timeout', dest='request_timeout', type=int,
                                     help='请求超时时间(秒)')

        return self.parser

    def load_from_file(self, config_path: str) -> None:
        """从配置文件加载配置

        Args:
            config_path: 配置文件路径
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"配置文件不存在: {config_path}")

        with open(config_path, 'r', encoding='utf-8') as file:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                file_config = yaml.safe_load(file)
            elif config_path.endswith('.json'):
                file_config = json.load(file)
            else:
                raise ValueError(f"不支持的配置文件格式: {config_path}")

        # 递归更新配置
        self._update_config(self.config, file_config)

    def _update_config(self, target: Dict, source: Dict) -> None:
        """递归更新配置字典

        Args:
            target: 目标配置字典
            source: 源配置字典
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_config(target[key], value)
            else:
                target[key] = value

    def parse_args(self) -> None:
        """解析命令行参数"""
        # 获取或创建解析器
        parser = self.get_parser()

        # 解析参数
        self.args = parser.parse_args()

        # 如果指定了配置文件，先加载配置文件
        if self.args.config_file:
            self.load_from_file(self.args.config_file)

        # 应用命令行参数覆盖配置文件
        self._apply_args_to_config()

    def _apply_args_to_config(self) -> None:
        """将命令行参数应用到配置中"""
        if not self.args:
            return

        # 更新基本配置
        if self.args.target_url:
            self.config['target_url'] = self.args.target_url

        if self.args.parallel_scan is not None:
            self.config['parallel_scan'] = self.args.parallel_scan

        # 更新扫描器启用/禁用状态
        if self.args.enable_scanners:
            for scanner in self.args.enable_scanners:
                if scanner in self.config['scanners']:
                    self.config['scanners'][scanner]['enabled'] = True

        if self.args.disable_scanners:
            for scanner in self.args.disable_scanners:
                if scanner in self.config['scanners']:
                    self.config['scanners'][scanner]['enabled'] = False

        # 更新报告配置
        if self.args.report_formats:
            self.config['reporting']['export_formats'] = self.args.report_formats

        if self.args.report_dir:
            self.config['reporting']['report_dir'] = self.args.report_dir

        # 更新请求超时
        if self.args.request_timeout:
            self.config['general']['request_timeout'] = self.args.request_timeout

    def set_target_url(self, url: str) -> None:
        """设置目标URL

        Args:
            url: 目标URL
        """
        self.config['target_url'] = url

    def get_enabled_scanners(self) -> List[str]:
        """获取启用的扫描器类型列表

        Returns:
            List[str]: 启用的扫描器类型列表
        """
        return [
            scanner_type for scanner_type, scanner_config in self.config['scanners'].items()
            if scanner_config.get('enabled', True)
        ]

    def get_scanner_config(self, scanner_type: str) -> Dict[str, Any]:
        """获取特定扫描器的配置

        Args:
            scanner_type: 扫描器类型

        Returns:
            Dict[str, Any]: 扫描器配置
        """
        return self.config['scanners'].get(scanner_type, {})

    def get_report_config(self) -> Dict[str, Any]:
        """获取报告配置

        Returns:
            Dict[str, Any]: 报告配置
        """
        return self.config['reporting']

    def get_general_config(self) -> Dict[str, Any]:
        """获取通用配置

        Returns:
            Dict[str, Any]: 通用配置
        """
        return self.config['general']

    def get_target_url(self) -> str:
        """获取目标URL

        Returns:
            str: 目标URL
        """
        return self.config['target_url']

    def is_parallel_scan(self) -> bool:
        """是否启用并行扫描

        Returns:
            bool: 是否启用并行扫描
        """
        return self.config.get('parallel_scan', True)