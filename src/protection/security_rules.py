# -*- coding: utf-8 -*-
# src/protection/security_rules.py
import re
from typing import Dict, List, Pattern, Any


class SecurityRules:
    """安全规则库，用于存储各种验证和净化规则"""

    # XSS攻击模式
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'onerror=',
        r'onload=',
        r'eval\(',
        r'document\.cookie',
        r'<img[^>]+src=[^>]+onerror=[^>]+>',
        r'<iframe[^>]*>',
        r'<svg[^>]*>',
    ]

    # SQL注入模式
    SQL_INJECTION_PATTERNS = [
        r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
        r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
        r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))',
        r'((\%27)|(\'))union',
        r'exec(\s|\+)+(s|x)p\w+',
        r'insert|update|delete|select|drop|truncate|alter',
    ]

    # 命令注入模式
    COMMAND_INJECTION_PATTERNS = [
        r'[&;`\\|*?~<>^()\[\]{}$\n\r]',
        r'(;|\||`|>|<|\$|\\|\/)',
        r'(cat|ls|pwd|echo|rm|grep|chmod|chown|sudo|su)\s',
    ]

    # 路径遍历模式
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%252e%252e%252f',
        r'%c0%ae%c0%ae%c0%af',
    ]

    # 信用卡验证规则 - 主要卡种前缀和长度
    CREDIT_CARD_RULES = {
        'VISA': {
            'pattern': r'^4[0-9]{12}(?:[0-9]{3})?$',
            'length': [13, 16]
        },
        'MASTERCARD': {
            'pattern': r'^5[1-5][0-9]{14}$',
            'length': [16]
        },
        'AMEX': {
            'pattern': r'^3[47][0-9]{13}$',
            'length': [15]
        },
        'DISCOVER': {
            'pattern': r'^6(?:011|5[0-9]{2})[0-9]{12}$',
            'length': [16]
        },
        'JCB': {
            'pattern': r'^(?:2131|1800|35\d{3})\d{11}$',
            'length': [15, 16]
        }
    }

    # 电子邮件验证模式
    EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    # URL验证模式
    URL_PATTERN = r'^(https?):\/\/[^\s/$.?#].[^\s]*$'

    # 手机号码验证模式（简化，实际应根据国家/地区定制）
    PHONE_PATTERN = r'^\+?[0-9]{6,15}$'

    # 敏感HTTP头部
    SENSITIVE_HEADERS = [
        'Authorization',
        'Cookie',
        'X-API-Key',
        'X-Auth-Token',
        'Set-Cookie',
    ]

    # HTML实体编码字典
    HTML_ENTITY_ENCODING = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;',
        '/': '&#x2F;',
        '`': '&#96;',
    }

    @classmethod
    def compile_regex_patterns(cls, patterns: List[str]) -> List[Pattern]:
        """编译正则表达式模式列表

        Args:
            patterns: 正则表达式模式字符串列表

        Returns:
            List[Pattern]: 编译后的正则表达式对象列表
        """
        return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    @classmethod
    def get_compiled_xss_patterns(cls) -> List[Pattern]:
        """获取编译后的XSS模式

        Returns:
            List[Pattern]: 编译后的XSS模式列表
        """
        return cls.compile_regex_patterns(cls.XSS_PATTERNS)

    @classmethod
    def get_compiled_sql_injection_patterns(cls) -> List[Pattern]:
        """获取编译后的SQL注入模式

        Returns:
            List[Pattern]: 编译后的SQL注入模式列表
        """
        return cls.compile_regex_patterns(cls.SQL_INJECTION_PATTERNS)