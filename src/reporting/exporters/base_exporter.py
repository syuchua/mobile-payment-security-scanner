from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseExporter(ABC):
    """报告导出器基类"""

    @abstractmethod
    def export(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        导出报告到指定格式

        Args:
            report_data: 报告数据
            output_path: 输出路径

        Returns:
            str: 生成的文件路径
        """
        pass