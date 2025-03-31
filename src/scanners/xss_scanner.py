# -*- coding: utf-8 -*-
# src/scanners/xss_scanner.py - 增加XSS检测逻辑
def scan_for_xss(self, url):
    test_payloads = ["<script>alert(1)</script>", "javascript:alert(1)"]
    vulnerable_endpoints = []

    # 检查用户数据端点
    test_endpoint = f"{url}/api/user_data?username="
    for payload in test_payloads:
        response = requests.get(f"{test_endpoint}{payload}")
        if payload in response.text:
            vulnerable_endpoints.append(("/api/user_data", "中", "反射型XSS漏洞"))

    return vulnerable_endpoints