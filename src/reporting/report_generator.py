import matplotlib.pyplot as plt
import pandas as pd
import io
from datetime import datetime
from typing import List, Dict, Any
from src.core.vulnerability_scanner import VulnerabilityResult


class ReportGenerator:
    """安全扫描报告生成器"""

    def __init__(self, target_url: str):
        """初始化报告生成器

        Args:
            target_url: 扫描的目标URL
        """
        self.target_url = target_url
        self.scan_date = datetime.now()
        self.figures = {}  # 存储生成的图表

    def generate_report(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """生成安全扫描报告

        Args:
            vulnerabilities: 扫描发现的漏洞列表

        Returns:
            包含报告内容的字典
        """
        # 创建报告数据结构
        report = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_date": self.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
                "total_vulnerabilities": len(vulnerabilities)
            },
            "summary": self._generate_summary(vulnerabilities),
            "charts": self._generate_charts(vulnerabilities),
            "vulnerabilities": self._format_vulnerabilities(vulnerabilities)
        }

        return report

    def _generate_summary(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """生成扫描摘要统计信息"""
        if not vulnerabilities:
            return {
                "total": 0,
                "by_severity": {"高": 0, "中": 0, "低": 0},
                "by_type": {}
            }

        # 按严重程度统计
        severity_counts = {"高": 0, "中": 0, "低": 0}
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1

        # 按漏洞类型统计
        type_counts = {}
        for vuln in vulnerabilities:
            if vuln.vulnerability_type in type_counts:
                type_counts[vuln.vulnerability_type] += 1
            else:
                type_counts[vuln.vulnerability_type] = 1

        return {
            "total": len(vulnerabilities),
            "by_severity": severity_counts,
            "by_type": type_counts
        }

    def _generate_charts(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """生成图表"""
        charts = {}

        if not vulnerabilities:
            return charts

        # 创建漏洞严重程度分布图
        severity_chart = self._create_severity_chart(vulnerabilities)
        charts["severity_distribution"] = severity_chart

        # 创建漏洞类型分布图
        type_chart = self._create_type_chart(vulnerabilities)
        charts["type_distribution"] = type_chart

        return charts

    def _create_severity_chart(self, vulnerabilities: List[VulnerabilityResult]) -> bytes:
        """创建漏洞严重程度分布条形图"""
        # 统计各严重程度的漏洞数量
        severity_counts = {"高": 0, "中": 0, "低": 0}
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1

        # 创建并保存图表
        plt.figure(figsize=(8, 5))
        bars = plt.bar(
            list(severity_counts.keys()),
            list(severity_counts.values()),
            color=['#ff4d4d', '#ffcc00', '#4da6ff']
        )

        # 添加数据标签
        for bar in bars:
            height = bar.get_height()
            plt.text(
                bar.get_x() + bar.get_width() / 2.,
                height,
                f'{height}',
                ha='center',
                va='bottom'
            )

        plt.title("按严重程度划分的漏洞分布")
        plt.xlabel("严重程度")
        plt.ylabel("漏洞数量")
        plt.tight_layout()

        # 将图表保存到内存缓冲区
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        plt.close()

        return buf.getvalue()

    def _create_type_chart(self, vulnerabilities: List[VulnerabilityResult]) -> bytes:
        """创建漏洞类型分布饼图"""
        # 统计各类型的漏洞数量
        type_counts = {}
        for vuln in vulnerabilities:
            if vuln.vulnerability_type in type_counts:
                type_counts[vuln.vulnerability_type] += 1
            else:
                type_counts[vuln.vulnerability_type] = 1

        # 创建并保存图表
        plt.figure(figsize=(10, 7))
        plt.pie(
            list(type_counts.values()),
            labels=list(type_counts.keys()),
            autopct='%1.1f%%',
            startangle=140,
            shadow=True
        )
        plt.axis('equal')  # 确保饼图是圆的
        plt.title("漏洞类型分布")
        plt.tight_layout()

        # 将图表保存到内存缓冲区
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        plt.close()

        return buf.getvalue()

    def _format_vulnerabilities(self, vulnerabilities: List[VulnerabilityResult]) -> List[Dict[str, Any]]:
        """格式化漏洞详情"""
        # 按严重程度排序
        severity_order = {"高": 3, "中": 2, "低": 1}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.severity, 0),
            reverse=True
        )

        # 转换为字典列表
        formatted_vulns = []
        for i, vuln in enumerate(sorted_vulns, 1):
            formatted_vulns.append({
                "id": i,
                "type": vuln.vulnerability_type,
                "severity": vuln.severity,
                "description": vuln.description,
                "affected_endpoint": vuln.affected_endpoint,
                "details": vuln.details,
                "recommendations": vuln.recommendations
            })

        return formatted_vulns