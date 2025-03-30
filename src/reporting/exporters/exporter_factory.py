from typing import Dict, Any
from .base_exporter import BaseExporter
from .pdf_exporter import PDFExporter
from .html_exporter import HTMLExporter


class ExporterFactory:
    """导出器工厂类"""

    @staticmethod
    def create_exporter(format_type: str) -> BaseExporter:
        """
        根据格式类型创建相应的导出器

        Args:
            format_type: 导出格式类型 ('pdf' 或 'html')

        Returns:
            BaseExporter: 对应的导出器实例

        Raises:
            ValueError: 如果格式类型不支持
        """
        if format_type.lower() == 'pdf':
            return PDFExporter()
        elif format_type.lower() == 'html':
            return HTMLExporter()
        else:
            raise ValueError(f"不支持的导出格式: {format_type}")