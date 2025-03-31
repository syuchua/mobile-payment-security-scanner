# -*- coding: utf-8 -*-
import os
import logging


class Config:
    """安全扫描器配置类"""

    # 基础URL配置（确保指向正确的支付系统地址）
    BASE_URL = "http://localhost:5000"  # 修改为支付系统实际运行的地址

    # 扫描目标目录配置
    SCAN_DIRECTORIES = ["src", "basic"]

    # 超时设置
    REQUEST_TIMEOUT = 10  # 秒

    # 请求头配置
    DEFAULT_HEADERS = {
        "User-Agent": "Security-Scanner/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # 身份验证信息
    AUTH_CREDENTIALS = {
        "username": "test",
        "password": "test"
    }

    # 支付系统API端点列表（从basic/routes.py提取）
    TARGET_ENDPOINTS = [
        # 基础版支付系统端点
        "/api/register",
        "/api/login",
        "/api/cards",
        "/api/payment/process",
        "/api/transactions"
    ]

    # SQL注入扫描配置
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1",
        "admin' --",
        "1; DROP TABLE users",
        "1' UNION SELECT 1,username,password FROM users --"
    ]

    # 敏感信息扫描配置
    SENSITIVE_PATTERNS = {
        "信用卡号": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "CVV": r'\b"cvv"\s*:\s*"\d{3,4}"\b',
        "密码": r'\b"password"\s*:\s*"[^"]+"\b'
    }

    # 日志设置
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE = "security_scan.log"

    @classmethod
    def get_scan_results_path(cls):
        """获取扫描结果保存路径"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, "results")