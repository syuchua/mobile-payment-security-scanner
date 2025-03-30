import pytest
from src.core.network_interceptor import NetworkInterceptor
from src.vulnerabilities.xss import XSSScanner
from unittest.mock import MagicMock

@pytest.fixture
def interceptor():
    # 创建一个模拟的 NetworkInterceptor 实例
    mock_interceptor = MagicMock(spec=NetworkInterceptor)
    return mock_interceptor

def test_xss_scanner(interceptor):
    # 设置模拟的响应
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Your input: <script>alert('XSS')</script> was received"
    interceptor.intercept_request.return_value = mock_response

    # 创建 XSSScanner 实例
    scanner = XSSScanner(interceptor)

    # 执行扫描
    vulnerabilities = scanner.scan()

    # 验证扫描结果
    assert len(vulnerabilities) > 0
    assert vulnerabilities[0].vulnerability_type == "XSS跨站脚本"
    assert vulnerabilities[0].severity == "高"
    assert vulnerabilities[0].details["载荷"] in scanner.payloads