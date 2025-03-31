# -*- coding: utf-8 -*-
# src/protection/input_validator.py
import re
import logging
from typing import Any, Dict, List, Optional, Union, Pattern
from src.protection.security_rules import SecurityRules


class InputValidator:
    """输入验证器，验证输入数据的有效性和安全性"""

    def __init__(self):
        """初始化输入验证器"""
        self.logger = logging.getLogger(__name__)

        # 编译常用正则表达式以提高性能
        self.email_pattern = re.compile(SecurityRules.EMAIL_PATTERN)
        self.url_pattern = re.compile(SecurityRules.URL_PATTERN)
        self.phone_pattern = re.compile(SecurityRules.PHONE_PATTERN)

        # 编译XSS和SQL注入模式
        self.xss_patterns = SecurityRules.get_compiled_xss_patterns()
        self.sql_patterns = SecurityRules.get_compiled_sql_injection_patterns()

    def validate_not_empty(self, value: Any) -> bool:
        """验证值不为空

        Args:
            value: 要验证的值

        Returns:
            bool: 如果值不为空则返回True
        """
        if value is None:
            return False

        if isinstance(value, str) and not value.strip():
            return False

        return True

    def validate_length(self, value: str, min_length: int = 0, max_length: Optional[int] = None) -> bool:
        """验证字符串长度

        Args:
            value: 要验证的字符串
            min_length: 最小长度
            max_length: 最大长度，如果为None则不限制最大长度

        Returns:
            bool: 如果字符串长度在指定范围内则返回True
        """
        if not isinstance(value, str):
            return False

        length = len(value)

        if length < min_length:
            return False

        if max_length is not None and length > max_length:
            return False

        return True

    def validate_numeric(self, value: str) -> bool:
        """验证字符串是否为数字

        Args:
            value: 要验证的字符串

        Returns:
            bool: 如果字符串是数字则返回True
        """
        if not isinstance(value, str):
            return False

        return value.isdigit()

    def validate_decimal(self, value: str) -> bool:
        """验证字符串是否为小数

        Args:
            value: 要验证的字符串

        Returns:
            bool: 如果字符串是小数则返回True
        """
        if not isinstance(value, str):
            return False

        try:
            float(value)
            return True
        except ValueError:
            return False

    def validate_email(self, value: str) -> bool:
        """验证电子邮件地址

        Args:
            value: 要验证的电子邮件地址

        Returns:
            bool: 如果是有效的电子邮件地址则返回True
        """
        if not isinstance(value, str):
            return False

        return bool(self.email_pattern.match(value))

    def validate_url(self, value: str) -> bool:
        """验证URL

        Args:
            value: 要验证的URL

        Returns:
            bool: 如果是有效的URL则返回True
        """
        if not isinstance(value, str):
            return False

        return bool(self.url_pattern.match(value))

    def validate_phone(self, value: str) -> bool:
        """验证电话号码

        Args:
            value: 要验证的电话号码

        Returns:
            bool: 如果是有效的电话号码则返回True
        """
        if not isinstance(value, str):
            return False

        return bool(self.phone_pattern.match(value))

    def validate_credit_card(self, value: str) -> bool:
        """验证信用卡号（使用Luhn算法和前缀验证）

        Args:
            value: 要验证的信用卡号

        Returns:
            bool: 如果是有效的信用卡号则返回True
        """
        if not isinstance(value, str):
            return False

        # 移除空格和连字符
        card_number = value.replace(' ', '').replace('-', '')

        # 检查是否只包含数字
        if not card_number.isdigit():
            return False

        # 验证长度
        card_length = len(card_number)
        valid_length = False

        # 验证卡号前缀和长度
        for card_type, rules in SecurityRules.CREDIT_CARD_RULES.items():
            pattern = re.compile(rules['pattern'])
            if pattern.match(card_number) and card_length in rules['length']:
                valid_length = True
                break

        if not valid_length:
            return False

        # 应用Luhn算法
        digits = [int(d) for d in card_number]
        odd_digits = digits[-1::-2]  # 从右向左，奇数位
        even_digits = digits[-2::-2]  # 从右向左，偶数位

        # 偶数位数字乘以2，如果结果大于9，则减去9
        doubles = [(d * 2) if d * 2 <= 9 else (d * 2 - 9) for d in even_digits]

        # 所有数字之和必须是10的倍数
        checksum = sum(odd_digits) + sum(doubles)

        return checksum % 10 == 0

    def validate_against_regex(self, value: str, pattern: Union[str, Pattern]) -> bool:
        """使用正则表达式验证字符串

        Args:
            value: 要验证的字符串
            pattern: 正则表达式模式（字符串或已编译的正则表达式）

        Returns:
            bool: 如果字符串匹配正则表达式则返回True
        """
        if not isinstance(value, str):
            return False

        if isinstance(pattern, str):
            pattern = re.compile(pattern)

        return bool(pattern.match(value))

    def validate_enum(self, value: Any, allowed_values: List[Any]) -> bool:
        """验证值是否在允许的值列表中

        Args:
            value: 要验证的值
            allowed_values: 允许的值列表

        Returns:
            bool: 如果值在允许的值列表中则返回True
        """
        return value in allowed_values

    def detect_xss(self, value: str) -> bool:
        """检测字符串中是否存在XSS攻击模式

        Args:
            value: 要检测的字符串

        Returns:
            bool: 如果字符串中包含XSS攻击模式则返回True
        """
        if not isinstance(value, str):
            return False

        for pattern in self.xss_patterns:
            if pattern.search(value):
                self.logger.warning(f"检测到潜在XSS攻击模式: {value}")
                return True

        return False

    def detect_sql_injection(self, value: str) -> bool:
        """检测字符串中是否存在SQL注入攻击模式

        Args:
            value: 要检测的字符串

        Returns:
            bool: 如果字符串中包含SQL注入攻击模式则返回True
        """
        if not isinstance(value, str):
            return False

        for pattern in self.sql_patterns:
            if pattern.search(value):
                self.logger.warning(f"检测到潜在SQL注入攻击模式: {value}")
                return True

        return False

    def validate_payment_data(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """验证支付数据的有效性和安全性

        Args:
            data: 支付数据字典

        Returns:
            Dict[str, List[str]]: 验证错误信息字典，键为字段名，值为错误消息列表
        """
        errors = {}

        # 验证金额
        if 'amount' in data:
            if not self.validate_not_empty(data['amount']):
                errors.setdefault('amount', []).append("金额不能为空")
            elif not self.validate_decimal(data['amount']):
                errors.setdefault('amount', []).append("金额必须是有效的数值")
        else:
            errors.setdefault('amount', []).append("缺少金额字段")

        # 验证卡号
        if 'card_number' in data:
            card_number = data['card_number'].replace('-', '').replace(' ', '')
            if not self.validate_not_empty(card_number):
                errors.setdefault('card_number', []).append("卡号不能为空")
            elif not self.validate_credit_card(card_number):
                errors.setdefault('card_number', []).append("无效的信用卡号")

        # 验证描述
        if 'description' in data and data['description']:
            description = data['description']
            if self.detect_xss(description):
                errors.setdefault('description', []).append("描述包含潜在的XSS攻击模式")
            elif self.detect_sql_injection(description):
                errors.setdefault('description', []).append("描述包含潜在的SQL注入攻击模式")

        # 验证用户ID
        if 'user_id' in data:
            if not self.validate_not_empty(data['user_id']):
                errors.setdefault('user_id', []).append("用户ID不能为空")
            elif self.detect_sql_injection(data['user_id']):
                errors.setdefault('user_id', []).append("用户ID包含潜在的SQL注入攻击模式")

        return errors