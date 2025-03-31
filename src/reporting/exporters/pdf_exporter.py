# -*- coding: utf-8 -*-
import os
import base64
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.platypus import PageBreak, ListFlowable, ListItem
from reportlab.lib.units import inch, cm
from io import BytesIO
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

from .base_exporter import BaseExporter


class PDFExporter(BaseExporter):
    """PDF格式报告导出器"""

    def export(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        导出报告为PDF格式

        Args:
            report_data: 报告数据
            output_path: 输出路径

        Returns:
            str: 生成的PDF文件路径
        """
        # 确保输出目录存在
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # 注册中文字体
        pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))

        # 创建PDF文档
        doc = SimpleDocTemplate(output_path, pagesize=A4,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=72)

        # 获取样式
        styles = getSampleStyleSheet()

        # 添加支持中文的样式
        styles.add(ParagraphStyle(
            name='ChineseHeading1',
            parent=styles['Heading1'],
            fontName='STSong-Light',
            fontSize=18,
            spaceAfter=12
        ))

        styles.add(ParagraphStyle(
            name='ChineseHeading2',
            parent=styles['Heading2'],
            fontName='STSong-Light',
            fontSize=16,
            spaceAfter=10
        ))

        styles.add(ParagraphStyle(
            name='ChineseHeading3',
            parent=styles['Heading3'],
            fontName='STSong-Light',
            fontSize=14,
            spaceAfter=8
        ))

        styles.add(ParagraphStyle(
            name='ChineseNormal',
            parent=styles['Normal'],
            fontName='STSong-Light',
            fontSize=10
        ))

        styles.add(ParagraphStyle(
            name='ChineseNormal_Bold',
            parent=styles['Normal'],
            fontName='STSong-Light',
            fontSize=10,
            fontWeight='bold'
        ))

        # 创建报告内容
        elements = []

        # 添加报告标题
        elements.append(Paragraph("安全扫描报告", styles["ChineseHeading1"]))
        elements.append(Spacer(1, 0.25 * inch))

        # 添加扫描信息
        scan_info = report_data["scan_info"]
        elements.append(Paragraph("扫描信息", styles["ChineseHeading2"]))
        elements.append(Spacer(1, 0.1 * inch))

        # 扫描信息表格
        info_data = [
            ["目标URL", scan_info["target_url"]],
            ["扫描时间", scan_info["scan_date"]],
            ["漏洞总数", str(scan_info["total_vulnerabilities"])]
        ]
        info_table = Table(info_data, colWidths=[100, 350])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('FONT', (0, 0), (-1, -1), 'STSong-Light'),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 0.2 * inch))

        # 添加摘要部分
        summary = report_data["summary"]
        elements.append(Paragraph("漏洞摘要", styles["ChineseHeading2"]))
        elements.append(Spacer(1, 0.1 * inch))

        # 严重程度统计表格
        elements.append(Paragraph("按严重程度划分", styles["ChineseHeading3"]))
        elements.append(Spacer(1, 0.1 * inch))

        severity_data = [["严重程度", "数量"]]
        for severity, count in summary["by_severity"].items():
            severity_data.append([severity, str(count)])

        sev_table = Table(severity_data, colWidths=[100, 100])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('FONT', (0, 0), (-1, -1), 'STSong-Light'),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 0.2 * inch))

        # 漏洞类型统计表格
        elements.append(Paragraph("按漏洞类型划分", styles["ChineseHeading3"]))
        elements.append(Spacer(1, 0.1 * inch))

        type_data = [["漏洞类型", "数量"]]
        for vuln_type, count in summary["by_type"].items():
            type_data.append([vuln_type, str(count)])

        type_table = Table(type_data, colWidths=[300, 100])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('FONT', (0, 0), (-1, -1), 'STSong-Light'),
        ]))
        elements.append(type_table)
        elements.append(Spacer(1, 0.2 * inch))

        # 添加图表
        if "charts" in report_data and report_data["charts"]:
            elements.append(Paragraph("图表与统计", styles["ChineseHeading2"]))
            elements.append(Spacer(1, 0.1 * inch))

            # 添加严重程度分布图
            if "severity_distribution" in report_data["charts"]:
                elements.append(Paragraph("漏洞严重程度分布", styles["ChineseHeading3"]))
                elements.append(Spacer(1, 0.1 * inch))
                chart_data = report_data["charts"]["severity_distribution"]
                img = Image(BytesIO(chart_data))
                img.drawHeight = 3 * inch
                img.drawWidth = 5 * inch
                elements.append(img)
                elements.append(Spacer(1, 0.2 * inch))

            # 添加类型分布图
            if "type_distribution" in report_data["charts"]:
                elements.append(Paragraph("漏洞类型分布", styles["ChineseHeading3"]))
                elements.append(Spacer(1, 0.1 * inch))
                chart_data = report_data["charts"]["type_distribution"]
                img = Image(BytesIO(chart_data))
                img.drawHeight = 4 * inch
                img.drawWidth = 6 * inch
                elements.append(img)

            elements.append(PageBreak())

        # 漏洞详情
        vulnerabilities = report_data["vulnerabilities"]
        if vulnerabilities:
            elements.append(Paragraph("漏洞详细信息", styles["ChineseHeading2"]))
            elements.append(Spacer(1, 0.1 * inch))

            # 添加各个漏洞的详细信息
            for vuln in vulnerabilities:
                elements.append(Paragraph(f"漏洞 #{vuln['id']}: {vuln['type']}", styles["ChineseHeading3"]))
                elements.append(Spacer(1, 0.05 * inch))

                vuln_data = [
                    ["严重程度", vuln["severity"]],
                    ["描述", vuln["description"]],
                    ["受影响端点", vuln["affected_endpoint"]]
                ]

                vuln_table = Table(vuln_data, colWidths=[100, 350])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('FONT', (0, 0), (-1, -1), 'STSong-Light'),
                ]))
                elements.append(vuln_table)
                elements.append(Spacer(1, 0.1 * inch))

                # 详情
                elements.append(Paragraph("详情:", styles["ChineseNormal_Bold"]))
                details_list = []
                for key, value in vuln["details"].items():
                    details_list.append(f"{key}: {value}")

                if details_list:
                    detail_items = [ListItem(Paragraph(item, styles["ChineseNormal"])) for item in details_list]
                    elements.append(ListFlowable(detail_items, bulletType='bullet', leftIndent=20))
                    elements.append(Spacer(1, 0.1 * inch))

                # 修复建议
                elements.append(Paragraph("建议修复方案:", styles["ChineseNormal_Bold"]))
                if vuln["recommendations"]:
                    rec_items = [ListItem(Paragraph(rec, styles["ChineseNormal"])) for rec in vuln["recommendations"]]
                    elements.append(ListFlowable(rec_items, bulletType='bullet', leftIndent=20))

                elements.append(Spacer(1, 0.2 * inch))
                elements.append(Paragraph("", styles["ChineseNormal"]))
        else:
            elements.append(Paragraph("未发现任何安全漏洞。", styles["ChineseNormal"]))

        # 构建PDF
        doc.build(elements)

        return output_path