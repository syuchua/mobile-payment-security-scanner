# src/protection/input_sanitizer.py
import re
import html
import logging
from typing import Any, Dict, List, Optional, Union
from src.protection.security_rules import SecurityRules
from src.protection.input_validator import InputValidator


class InputSanitizer:
    """输入净化器，用于清理和转义不安全的输入数据"""

    def __init__(self):
        """初始化输入净化器"""
        self.logger = logging.getLogger(__name__)
        self.validator = InputValidator()

    def strip_html(self, value: str) -> str:
        """移除HTML标签

        Args:
            value: 要处理的字符串

        Returns:
            str: 移除HTML标签后的字符串
        """
        if not isinstance(value, str):
            return str(value)

        # 使用正则表达式移除所有HTML标签
        return re.sub(r'<[^>]*>', '', value)

    def escape_html(self, value: str) -> str:
        """转义HTML特殊字符

        Args:
            value: 要处理的字符串

        Returns:
            str: 转义后的字符串
        """
        if not isinstance(value, str):
            return str(value)

        return html.escape(value)

    def sanitize_sql(self, value: str) -> str:
        """净化可能的SQL注入攻击

        Args:
            value: 要处理的字符串

        Returns:
            str: 净化后的字符串
        """
        if not isinstance(value, str):
            return str(value)

        # 移除或转义SQL注入攻击常用字符
        sanitized = value
        sanitized = sanitized.replace("'", "''")  # 转义单引号
        sanitized = sanitized.replace(";", "")  # 移除分号
        sanitized = sanitized.replace("--", "")  # 移除注释符
        sanitized = sanitized.replace("/*", "")  # 移除块注释开始
        sanitized = sanitized.replace("*/", "")  # 移除块注释结束
        sanitized = sanitized.replace("xp_", "")  # 移除存储过程前缀

        # 移除常见SQL关键字（使用正则表达式匹配整个单词）
        keywords = [
            "SELECT", "UPDATE", "INSERT", "DELETE", "DROP", "ALTER",
            "EXEC", "UNION", "CREATE", "WHERE", "OR", "AND"
        ]
        pattern = r'\b(' + '|'.join(keywords) + r')\b'
        sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        return sanitized

    def sanitize_script(self, value: str) -> str:
        """净化JavaScript代码

        Args:
            value: 要处理的字符串

        Returns:
            str: 净化后的字符串
        """
        if not isinstance(value, str):
            return str(value)

        # 移除<script>标签及内容
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)

        # 移除事件处理属性
        events = [
            "onload", "onclick", "onmouseover", "onfocus", "onblur", "onchange",
            "onsubmit", "onkeyup", "onkeydown", "onkeypress", "onerror"
        ]
        for event in events:
            sanitized = re.sub(fr'{event}\s*=\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)

        # 移除javascript:协议
        sanitized = re.sub(r'javascript:[^\s"\']*', '', sanitized, flags=re.IGNORECASE)

        return sanitized

    def sanitize_filename(self, value: str) -> str:
        """净化文件名，防止路径遍历攻击

        Args:
            value: 要处理的文件名

        Returns:
            str: 净化后的文件名
        """
        if not isinstance(value, str):
            return str(value)

        # 移除路径分隔符和其他不安全字符
        sanitized = re.sub(r'[/\\:*?"<>|]', '', value)

        # 移除连续的点（防止路径遍历）
        sanitized = re.sub(r'\.{2,}', '.', sanitized)

        return sanitized

    def sanitize_credit_card(self, value: str) -> str:
        """清理并格式化信用卡号

        Args:
            value: 要处理的信用卡号

        Returns:
            str: 净化后的信用卡号
        """
        if not isinstance(value, str):
            return str(value)

        # 移除所有非数字字符
        digits_only = re.sub(r'\D', '', value)

        # 验证是否是有效的信用卡号
        if not self.validator.validate_credit_card(digits_only):
            self.logger.warning(f"无效的信用卡号格式: {value}")
            # 可以选择返回空字符串或原值
            return digits_only

        # 格式化为4位一组的形式
        formatted = ''
        for i in range(0, len(digits_only), 4):
            if i > 0:
                formatted += '-'
            formatted += digits_only[i:i + 4]

        return formatted

    def sanitize_amount(self, value: str) -> str:
        """净化并格式化金额

        Args:
            value: 要处理的金额

        Returns:
            str: 净化后的金额
        """
        if not isinstance(value, str):
            return str(value)

        # 移除除数字和小数点外的所有字符
        amount = re.sub(r'[^\d.]', '', value)

        # 确保只有一个小数点
        parts = amount.split('.')
        if len(parts) > 2:
            amount = parts[0] + '.' + parts[1]

        # 尝试转换为浮点数并格式化为两位小数
        try:
            return "{:.2f}".format(float(amount))
        except ValueError:
            self.logger.warning(f"无效的金额格式: {value}")
            return "0.00"

    def sanitize_payment_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """净化支付数据

        Args:
            data: 支付数据字典

        Returns:
            Dict[str, Any]: 净化后的支付数据
        """
        if not isinstance(data, dict):
            self.logger.error("支付数据必须是字典类型")
            return {}

        sanitized_data = {}

        # 净化金额
        if 'amount' in data:
            sanitized_data['amount'] = self.sanitize_amount(str(data['amount']))

        # 净化卡号
        if 'card_number' in data:
            sanitized_data['card_number'] = self.sanitize_credit_card(str(data['card_number']))

        # 净化描述
        if 'description' in data:
            # 首先移除任何脚本和HTML
            clean_description = self.sanitize_script(str(data['description']))
            clean_description = self.strip_html(clean_description)
            # 然后转义剩余的特殊字符
            sanitized_data['description'] = self.escape_html(clean_description)

        # 净化用户ID
        if 'user_id' in data:
            # 用户ID通常只需要字母数字字符
            user_id = str(data['user_id'])
            sanitized_data['user_id'] = re.sub(r'[^\w-]', '', user_id)

        return sanitized_data

    def sanitize_dict(self, data: Dict[str, Any], recursive: bool = True) -> Dict[str, Any]:
        """递归净化字典中的所有字符串值

        Args:
            data: 要净化的字典
            recursive: 是否递归处理嵌套字典和列表

        Returns:
            Dict[str, Any]: 净化后的字典
        """
        if not isinstance(data, dict):
            self.logger.error("数据必须是字典类型")
            return {}

        sanitized = {}

        for key, value in data.items():
            # 净化字典键
            clean_key = self.sanitize_sql(str(key))

            if isinstance(value, str):
                # 净化字符串值
                sanitized[clean_key] = self.escape_html(self.sanitize_script(value))
            elif isinstance(value, dict) and recursive:
                # 递归净化嵌套字典
                sanitized[clean_key] = self.sanitize_dict(value, recursive)
            elif isinstance(value, list) and recursive:
                # 递归净化列表中的项
                sanitized[clean_key] = [
                    self.sanitize_dict(item, recursive) if isinstance(item, dict)
                    else self.escape_html(self.sanitize_script(item)) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                # 保留原值（非字符串类型）
                sanitized[clean_key] = value

        return sanitized