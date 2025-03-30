import pytest
from src.core.network_interceptor import NetworkInterceptor
from src.vulnerabilities.sensitive_data import SensitiveDataScanner
from unittest.mock import MagicMock


@pytest.fixture
def interceptor():
    # 创建一个模拟的 NetworkInterceptor 实例
    mock_interceptor = MagicMock(spec=NetworkInterceptor)
    return mock_interceptor


def test_sensitive_data_scanner(interceptor):
    # 设置模拟的响应
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "User email: test@example.com, Credit card: 4111-1111-1111-1111"
    interceptor.intercept_request.return_value = mock_response

    # 创建 SensitiveDataScanner 实例
    scanner = SensitiveDataScanner(interceptor)

    # 执行扫描
    vulnerabilities = scanner.scan()

    # 验证扫描结果
    assert len(vulnerabilities) > 0
    assert vulnerabilities[0].vulnerability_type == "敏感信息泄露"
    assert vulnerabilities[0].severity == "高"

    # 修正:检查掩码后的邮箱格式
    assert "te**@example.com" in vulnerabilities[0].details["掩码示例"]