import pytest
from src.core.network_interceptor import NetworkInterceptor
from src.vulnerabilities.authentication import AuthenticationScanner
from unittest.mock import MagicMock

@pytest.fixture
def interceptor():
    # 创建一个模拟的 NetworkInterceptor 实例
    mock_interceptor = MagicMock(spec=NetworkInterceptor)
    return mock_interceptor

def test_authentication_scanner(interceptor):
    # 设置模拟的响应
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "token: abc123"
    interceptor.intercept_request.return_value = mock_response

    # 创建 AuthenticationScanner 实例
    scanner = AuthenticationScanner(interceptor)

    # 执行扫描
    vulnerabilities = scanner.scan()

    # 验证扫描结果
    assert len(vulnerabilities) > 0
    assert vulnerabilities[0].vulnerability_type == "弱凭证漏洞"
    assert vulnerabilities[0].severity == "高"
    assert vulnerabilities[0].details["用户名"] == "admin"