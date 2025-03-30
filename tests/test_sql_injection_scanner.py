import pytest
from src.core.network_interceptor import NetworkInterceptor
from src.vulnerabilities.injection import SQLInjectionScanner
from unittest.mock import MagicMock


@pytest.fixture
def interceptor():
    # 创建一个模拟的NetworkInterceptor实例
    mock_interceptor = MagicMock(spec=NetworkInterceptor)
    return mock_interceptor


def test_sql_injection_scanner(interceptor):
    # 设置模拟的响应
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "SQL syntax error"
    interceptor.intercept_request.return_value = mock_response

    # 创建SQLInjectionScanner实例
    scanner = SQLInjectionScanner(interceptor)

    # 执行扫描
    vulnerabilities = scanner.scan()

    # 验证扫描结果
    assert len(vulnerabilities) > 0
    assert vulnerabilities[0].vulnerability_type == "SQL注入"
    assert vulnerabilities[0].severity == "高"

    # 修改这一行，确认载荷是SQL注入测试字符串之一
    assert vulnerabilities[0].details["载荷"] in scanner.payloads