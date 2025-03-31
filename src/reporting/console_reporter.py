# -*- coding: utf-8 -*-
from typing import Dict, Any
import textwrap
from colorama import init, Fore, Style

# 初始化colorama
init()


class ConsoleReporter:
    """控制台报告显示器"""

    def __init__(self):
        """初始化控制台报告显示器"""
        # 颜色映射
        self.severity_colors = {
            "高": Fore.RED,
            "中": Fore.YELLOW,
            "低": Fore.BLUE
        }

    def display_report(self, report: Dict[str, Any]):
        """在控制台显示格式化的报告"""
        self._print_header(report["scan_info"])
        self._print_summary(report["summary"])
        self._print_vulnerabilities(report["vulnerabilities"])

    def _print_header(self, scan_info: Dict[str, Any]):
        """打印报告头部"""
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}安全扫描报告{Style.RESET_ALL}")
        print("=" * 80)
        print(f"目标: {scan_info['target_url']}")
        print(f"扫描时间: {scan_info['scan_date']}")
        print(f"发现漏洞总数: {scan_info['total_vulnerabilities']}")
        print("-" * 80)

    def _print_summary(self, summary: Dict[str, Any]):
        """打印摘要信息"""
        print(f"\n{Fore.CYAN}摘要信息{Style.RESET_ALL}")
        print("-" * 80)

        # 按严重程度统计
        print("按严重程度划分:")
        for severity, count in summary["by_severity"].items():
            color = self.severity_colors.get(severity, "")
            print(f"  {color}{severity}{Style.RESET_ALL}: {count}")

        # 按类型统计
        print("\n按漏洞类型划分:")
        for vuln_type, count in summary["by_type"].items():
            print(f"  {vuln_type}: {count}")

        print("-" * 80)

    def _print_vulnerabilities(self, vulnerabilities: list):
        """打印漏洞详情"""
        if not vulnerabilities:
            print(f"\n{Fore.GREEN}[恭喜] 未发现任何安全漏洞。{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}漏洞详细信息{Style.RESET_ALL}")
        print("-" * 80)

        for vuln in vulnerabilities:
            # 获取严重程度对应的颜色
            color = self.severity_colors.get(vuln["severity"], "")

            print(f"\n漏洞 #{vuln['id']}:")
            print(f"类型: {vuln['type']}")
            print(f"严重程度: {color}{vuln['severity']}{Style.RESET_ALL}")
            print(f"描述: {vuln['description']}")
            print(f"受影响端点: {vuln['affected_endpoint']}")

            # 打印详情
            print("详情:")
            for key, value in vuln["details"].items():
                print(f"  - {key}: {value}")

            # 打印修复建议
            print("建议修复方案:")
            for rec in vuln["recommendations"]:
                # 对长文本进行换行处理
                wrapped_text = textwrap.fill(rec, width=76, initial_indent="  - ", subsequent_indent="    ")
                print(wrapped_text)

            print("-" * 80)