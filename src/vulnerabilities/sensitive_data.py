# src/vulnerabilities/sensitive_data.py
from typing import List
import re
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.scanner_strategy import ScannerStrategy


class SensitiveDataScanner(ScannerStrategy):
    """敏感数据泄露扫描器"""

    def _get_scanner_name(self) -> str:
        return "敏感信息泄露扫描"

    def scan(self) -> List[VulnerabilityResult]:
        """执行敏感数据泄露扫描

        Returns:
            List[VulnerabilityResult]: 发现的敏感数据泄露漏洞列表
        """
        vulnerabilities = []

        # 扫描常见端点
        endpoints = [
            '/api/users', '/api/config', '/api/payments',
            '/users/profile', '/admin', '/settings',
            '/api/logs', '/debug', '/api/keys'
        ]

        # 定义敏感数据的正则表达式
        patterns = {
            "信用卡号": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            "API密钥": r'[\'\"](sk|pk|api|key|token|secret)_\w{32,}[\'"]',
            "电子邮件": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "密码哈希": r'\b[0-9a-fA-F]{32,64}\b',
            "JWT": r'eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}'
        }

        for endpoint in endpoints:
            try:
                # 发送请求
                response = self.interceptor.intercept_request(
                    'GET',
                    endpoint,
                    headers={'Content-Type': 'application/json'}
                )

                # 检查响应是否包含敏感数据
                found_data = self._scan_for_sensitive_data(response.text, patterns)

                if found_data:
                    for data_type, examples in found_data.items():
                        vulnerabilities.append(
                            VulnerabilityResult(
                                vulnerability_type="敏感信息泄露",
                                severity="高" if data_type in ["信用卡号", "API密钥", "密码哈希"] else "中",
                                description=f"检测到{data_type}泄露",
                                affected_endpoint=endpoint,
                                details={
                                    "数据类型": data_type,
                                    "发现实例数": len(examples),
                                    "示例": self._mask_sensitive_data(examples[0], data_type)
                                },
                                recommendations=[
                                    "对敏感信息进行加密存储",
                                    "实施适当的访问控制",
                                    "在响应中过滤敏感数据",
                                    "使用数据屏蔽技术"
                                ]
                            )
                        )
            except Exception as e:
                # 记录异常但继续扫描
                pass

        return vulnerabilities

    def _scan_for_sensitive_data(self, text: str, patterns: dict) -> dict:
        """扫描文本中的敏感数据"""
        result = {}

        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                result[data_type] = matches

        return result

    def _mask_sensitive_data(self, data: str, data_type: str) -> str:
        """对敏感数据进行掩码处理"""
        if data_type == "信用卡号":
            # 只显示后四位
            return "****-****-****-" + data[-4:]
        elif data_type in ["API密钥", "密码哈希", "JWT"]:
            # 只显示前几个和后几个字符
            return data[:4] + "..." + data[-4:]
        else:
            # 其他类型，保持原样
            return data