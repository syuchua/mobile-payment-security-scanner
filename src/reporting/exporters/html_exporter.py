import os
import base64
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

from .base_exporter import BaseExporter


class HTMLExporter(BaseExporter):
    """HTML格式报告导出器"""

    def export(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        导出报告为HTML格式

        Args:
            report_data: 报告数据
            output_path: 输出路径

        Returns:
            str: 生成的HTML文件路径
        """
        # 确保输出目录存在
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # 设置模板目录
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report_template.html")

        # 编码图表为base64以嵌入HTML
        encoded_charts = {}
        if "charts" in report_data:
            for chart_name, chart_data in report_data["charts"].items():
                encoded_charts[chart_name] = base64.b64encode(chart_data).decode('utf-8')

        # 渲染模板
        html_content = template.render(
            report=report_data,
            charts=encoded_charts,
            generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # 写入HTML文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path