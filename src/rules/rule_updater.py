# -*- coding: utf-8 -*-
# src/rules/rule_updater.py
import os
import json
import requests
import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime


class RuleUpdater:
    """规则更新管理器，负责检查和更新扫描规则"""

    def __init__(self, rule_base_dir: str = "rules",
                 update_url: str = "https://security-rules.example.com/api/latest",
                 config_manager=None):
        """初始化规则更新器

        Args:
            rule_base_dir: 规则存储目录
            update_url: 规则更新服务URL
            config_manager: 配置管理器实例，用于检查模拟模式
        """
        self.rule_base_dir = rule_base_dir
        self.update_url = update_url
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager

        # 确保规则目录存在
        os.makedirs(rule_base_dir, exist_ok=True)

        # 版本信息文件
        self.version_file = os.path.join(rule_base_dir, "version.json")

        # 初始化版本信息
        self._init_version_info()

    def _init_version_info(self) -> None:
        """初始化版本信息文件"""
        if not os.path.exists(self.version_file):
            version_info = {
                "last_update": datetime.now().isoformat(),
                "version": "1.0.0",
                "rules": {}
            }
            with open(self.version_file, 'w', encoding='utf-8') as f:
                json.dump(version_info, f, ensure_ascii=False, indent=2)

    def _is_mock_mode(self) -> bool:
        """检查是否处于模拟模式"""
        if self.config_manager and hasattr(self.config_manager, 'config'):
            return self.config_manager.config.get('general', {}).get('mock_mode', False)
        return False

    def check_for_updates(self) -> Dict[str, Any]:
        """检查是否有规则更新

        Returns:
            Dict[str, Any]: 更新状态信息
        """
        # 检查是否处于模拟模式
        if self._is_mock_mode():
            self.logger.info("模拟模式下跳过实际规则检查")
            return {
                "status": "update_available",
                "current_version": "1.0.0",
                "latest_version": "2023.10.1",
                "update_info": {
                    "version": "2023.10.1",
                    "rules": {
                        "sql_injection": {"url": "mock://rules/sql_injection.json"},
                        "xss": {"url": "mock://rules/xss.json"},
                        "csrf": {"url": "mock://rules/csrf.json"}
                    }
                }
            }

        try:
            # 获取当前版本信息
            with open(self.version_file, 'r', encoding='utf-8') as f:
                current_version = json.load(f)

            # 请求最新版本信息
            headers = {"If-Modified-Since": current_version["last_update"]}
            response = requests.get(self.update_url, headers=headers, timeout=10)

            if response.status_code == 304:  # 未修改
                return {"status": "up_to_date", "message": "规则已是最新版本"}

            if response.status_code == 200:
                latest_info = response.json()

                # 检查版本
                if latest_info["version"] > current_version["version"]:
                    return {
                        "status": "update_available",
                        "current_version": current_version["version"],
                        "latest_version": latest_info["version"],
                        "update_info": latest_info
                    }
                return {"status": "up_to_date", "message": "规则已是最新版本"}

            return {"status": "error", "message": f"检查更新失败，HTTP状态码: {response.status_code}"}

        except Exception as e:
            self.logger.error(f"检查规则更新时出错: {e}")
            return {"status": "error", "message": f"检查更新出错: {str(e)}"}

    def update_rules(self) -> Dict[str, Any]:
        """下载并更新规则

        Returns:
            Dict[str, Any]: 更新结果
        """
        # 检查是否处于模拟模式
        if self._is_mock_mode():
            self.logger.info("模拟模式下跳过实际规则更新")
            # 创建示例规则文件
            self._create_mock_rule_files()
            return {
                "status": "updated",
                "version": "2023.10.1",
                "rules_updated": ["sql_injection", "xss", "csrf", "sensitive_data"],
                "timestamp": datetime.now().isoformat()
            }

        # 先检查是否有更新
        check_result = self.check_for_updates()
        if check_result["status"] != "update_available":
            return check_result

        update_info = check_result["update_info"]
        try:
            # 下载各类规则
            rules_updated = []
            for rule_type, rule_info in update_info["rules"].items():
                rule_url = rule_info["url"]
                rule_file = os.path.join(self.rule_base_dir, f"{rule_type}.json")

                # 下载规则文件
                response = requests.get(rule_url, timeout=10)
                if response.status_code == 200:
                    with open(rule_file, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    rules_updated.append(rule_type)
                else:
                    self.logger.warning(f"下载规则 {rule_type} 失败，HTTP状态码: {response.status_code}")

            # 更新版本信息
            with open(self.version_file, 'w', encoding='utf-8') as f:
                update_info["last_update"] = datetime.now().isoformat()
                json.dump(update_info, f, ensure_ascii=False, indent=2)

            return {
                "status": "updated",
                "version": update_info["version"],
                "rules_updated": rules_updated,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"更新规则时出错: {e}")
            return {"status": "error", "message": f"更新规则出错: {str(e)}"}

    def _create_mock_rule_files(self):
        """创建模拟规则文件（仅用于模拟模式）"""
        # SQL注入规则
        sql_rules = {
            "name": "SQL注入检测规则",
            "version": "2023.10.1",
            "description": "用于检测SQL注入攻击的规则集",
            "patterns": [
                {"regex": "'\s*OR\s*'1'='1", "severity": "high", "description": "基本SQL注入模式"},
                {"regex": "UNION\s+SELECT", "severity": "high", "description": "UNION注入尝试"},
                {"regex": "--\s*$", "severity": "medium", "description": "SQL注释"}
            ]
        }

        # XSS规则
        xss_rules = {
            "name": "XSS检测规则",
            "version": "2023.10.1",
            "description": "用于检测跨站脚本攻击的规则集",
            "patterns": [
                {"regex": "<script[^>]*>", "severity": "high", "description": "直接脚本注入"},
                {"regex": "javascript:", "severity": "medium", "description": "JavaScript协议"},
                {"regex": "on(load|click|mouseover)=", "severity": "medium", "description": "事件处理注入"}
            ]
        }

        # 创建示例规则文件
        rule_files = {
            "sql_injection.json": sql_rules,
            "xss.json": xss_rules,
        }

        for filename, content in rule_files.items():
            file_path = os.path.join(self.rule_base_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(content, f, ensure_ascii=False, indent=2)
            self.logger.info(f"创建模拟规则文件: {file_path}")

    def get_rule_file(self, rule_type: str) -> Optional[str]:
        """获取特定类型规则的文件路径

        Args:
            rule_type: 规则类型

        Returns:
            Optional[str]: 规则文件路径，不存在则返回None
        """
        rule_file = os.path.join(self.rule_base_dir, f"{rule_type}.json")
        return rule_file if os.path.exists(rule_file) else None

    def load_rules(self, rule_type: str) -> Dict[str, Any]:
        """加载特定类型的规则

        Args:
            rule_type: 规则类型

        Returns:
            Dict[str, Any]: 规则数据，如果文件不存在则返回空字典
        """
        rule_file = self.get_rule_file(rule_type)
        if not rule_file:
            return {}

        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"加载规则文件 {rule_file} 出错: {e}")
            return {}