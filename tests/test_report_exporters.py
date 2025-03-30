import pytest
import os
import tempfile
from src.reporting.report_generator import ReportGenerator
from src.reporting.exporters.exporter_factory import ExporterFactory
from src.core.vulnerability_scanner import VulnerabilityResult

# 需要安装这些额外的依赖
from PyPDF2 import PdfReader  # 注意：较新版本使用PdfReader而不是PdfFileReader
from bs4 import BeautifulSoup


@pytest.fixture
def sample_report():
    """创建测试用的示例报告数据"""
    report_generator = ReportGenerator("https://example.com")

    # 创建一些测试漏洞数据
    vulnerabilities = [
        VulnerabilityResult(
            vulnerability_type="SQL注入漏洞",
            severity="高",
            description="发现可能的SQL注入点",
            affected_endpoint="/api/users",
            details={"参数": "id", "输入值": "1' OR '1'='1"},
            recommendations=["使用参数化查询", "实施输入验证"]
        ),
        VulnerabilityResult(
            vulnerability_type="XSS漏洞",
            severity="中",
            description="发现反射型XSS漏洞",
            affected_endpoint="/search",
            details={"参数": "q", "输入值": "<script>alert(1)</script>"},
            recommendations=["对输出进行HTML编码", "实施内容安全策略"]
        )
    ]

    return report_generator.generate_report(vulnerabilities)


def test_pdf_export(sample_report):
    """测试PDF报告导出功能"""
    # 使用临时文件
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp:
        output_path = temp.name

    try:
        # 导出PDF报告
        exporter = ExporterFactory.create_exporter('pdf')
        exporter.export(sample_report, output_path)

        # 验证PDF文件是否生成成功
        assert os.path.exists(output_path)
        assert os.path.getsize(output_path) > 10000  # 确保PDF有合理大小

        # 验证PDF结构
        with open(output_path, "rb") as f:
            reader = PdfReader(f)
            assert len(reader.pages) > 0  # 至少有一页
            # 检查文本长度而非内容
            text = reader.pages[0].extract_text()
            assert len(text) > 100
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)


def test_html_export(sample_report):
    """测试HTML报告导出功能"""
    # 使用临时文件
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp:
        output_path = temp.name

    try:
        # 导出HTML报告
        exporter = ExporterFactory.create_exporter('html')
        exporter.export(sample_report, output_path)

        # 验证HTML文件是否生成
        assert os.path.exists(output_path)
        assert os.path.getsize(output_path) > 0

        # 读取HTML文件并验证内容
        with open(output_path, "r", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")
            assert "安全扫描报告" in soup.title.string
            assert "SQL注入漏洞" in soup.text
            assert "XSS漏洞" in soup.text
            assert "https://example.com" in soup.text
    finally:
        # 测试完成后删除临时文件
        if os.path.exists(output_path):
            os.remove(output_path)