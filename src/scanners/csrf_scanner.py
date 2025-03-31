# -*- coding: utf-8 -*-
# src/scanners/csrf_scanner.py - 增加CSRF检测逻辑
def scan_for_csrf(self, url):
    vulnerable_endpoints = []

    # 检查更新资料端点是否要求CSRF令牌
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(f"{url}/api/update_profile", data={"name": "test"}, headers=headers)

    if response.status_code == 200:
        vulnerable_endpoints.append(("/api/update_profile", "中", "缺少CSRF保护"))

    return vulnerable_endpoints