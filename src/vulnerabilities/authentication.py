from typing import List
import time
from src.core.vulnerability_scanner import VulnerabilityResult
from src.core.scanner_strategy import ScannerStrategy


class AuthenticationScanner(ScannerStrategy):
    """认证安全漏洞扫描器"""

    def _get_scanner_name(self) -> str:
        return "认证安全漏洞扫描"

    def scan(self) -> List[VulnerabilityResult]:
        """执行认证安全扫描

        Returns:
            List[VulnerabilityResult]: 发现的认证安全漏洞列表
        """
        vulnerabilities = []

        # 测试常见的认证端点
        auth_endpoints = {
            '/api/login': {'method': 'POST', 'creds': {'username': 'test', 'password': 'password123'}},
            '/api/authenticate': {'method': 'POST', 'creds': {'email': 'test@example.com', 'password': 'password123'}},
            '/auth/token': {'method': 'POST', 'creds': {'username': 'test', 'password': 'password123'}}
        }

        # 检查常见的认证问题
        for endpoint, config in auth_endpoints.items():
            # 检查暴力破解防护
            brute_force_vuln = self._check_brute_force_protection(endpoint, config)
            if brute_force_vuln:
                vulnerabilities.append(brute_force_vuln)

            # 检查不安全的传输
            if not self._check_secure_transmission(endpoint):
                vulnerabilities.append(
                    VulnerabilityResult(
                        vulnerability_type="不安全的凭据传输",
                        severity="高",
                        description="凭据通过不安全的HTTP通道传输",
                        affected_endpoint=endpoint,
                        details={
                            "问题": "使用HTTP而非HTTPS传输敏感凭据",
                            "风险": "凭据可能被中间人攻击截获"
                        },
                        recommendations=[
                            "对所有包含敏感信息的请求使用HTTPS",
                            "实施HSTS策略",
                            "避免在URL中传递敏感信息"
                        ]
                    )
                )

            # 检查弱密码策略
            if self._check_weak_password_policy(endpoint, config):
                vulnerabilities.append(
                    VulnerabilityResult(
                        vulnerability_type="弱密码策略",
                        severity="中",
                        description="系统接受弱密码",
                        affected_endpoint=endpoint,
                        details={
                            "问题": "接受简单密码如'password123'",
                            "风险": "容易被字典攻击或暴力破解"
                        },
                        recommendations=[
                            "实施强密码策略",
                            "要求密码包含大小写字母、数字和特殊字符",
                            "实施密码定期更换机制",
                            "使用密码强度检查器"
                        ]
                    )
                )

        return vulnerabilities

    def _check_brute_force_protection(self, endpoint: str, config: dict) -> VulnerabilityResult:
        """检查是否存在暴力破解防护"""
        # 模拟多次失败登录
        for _ in range(5):
            try:
                self.interceptor.intercept_request(
                    config['method'],
                    endpoint,
                    json={'username': 'test', 'password': 'wrong_password'},
                    headers={'Content-Type': 'application/json'}
                )
                # 短暂等待，避免过于频繁的请求
                time.sleep(0.5)
            except Exception:
                pass

        # 尝试一次有效登录，看系统是否阻止
        try:
            response = self.interceptor.intercept_request(
                config['method'],
                endpoint,
                json=config['creds'],
                headers={'Content-Type': 'application/json'}
            )

            # 如果成功登录，说明没有暴力破解防护
            if response.status_code == 200:
                return VulnerabilityResult(
                    vulnerability_type="缺少暴力破解防护",
                    severity="高",
                    description="系统未实施暴力破解防护机制",
                    affected_endpoint=endpoint,
                    details={
                        "问题": "多次失败登录后仍可继续尝试",
                        "风险": "容易遭受密码暴力破解攻击"
                    },
                    recommendations=[
                        "实施账户锁定机制",
                        "在连续失败登录后增加延迟",
                        "实施验证码或其他人机验证",
                        "考虑使用双因素认证"
                    ]
                )
        except Exception:
            pass

        return None

    def _check_secure_transmission(self, endpoint: str) -> bool:
        """检查是否使用安全传输（HTTPS）"""
        return self.interceptor.target_url.startswith("https://")

    def _check_weak_password_policy(self, endpoint: str, config: dict) -> bool:
        """检查是否接受弱密码"""
        weak_passwords = ["password", "123456", "admin", "password123"]

        for password in weak_passwords:
            creds = config['creds'].copy()
            creds['password'] = password

            try:
                response = self.interceptor.intercept_request(
                    config['method'],
                    endpoint,
                    json=creds,
                    headers={'Content-Type': 'application/json'}
                )

                # 如果使用弱密码能够成功认证
                if response.status_code == 200:
                    return True
            except Exception:
                pass

        return False