# src/protection/security_monitor.py
import logging
import time
from typing import Dict, List, Any, Optional
from threading import Lock


class SecurityMonitor:
    """安全监控器，用于记录并分析安全事件"""

    def __init__(self):
        """初始化安全监控器"""
        self.logger = logging.getLogger(__name__)
        self.security_events = []
        self.ip_attempt_count = {}  # IP地址尝试次数
        self.lock = Lock()  # 用于线程安全

    def log_security_event(self, event_type: str, details: Dict[str, Any],
                           severity: str = "info", ip_address: Optional[str] = None) -> None:
        """记录安全事件

        Args:
            event_type: 事件类型
            details: 事件详细信息
            severity: 事件严重程度（info, warning, error, critical）
            ip_address: 关联的IP地址
        """
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "ip_address": ip_address
        }

        # 写入日志
        log_message = f"安全事件: {event_type}, 严重程度: {severity}"
        if ip_address:
            log_message += f", IP: {ip_address}"

        if severity == "info":
            self.logger.info(log_message)
        elif severity == "warning":
            self.logger.warning(log_message)
        elif severity == "error":
            self.logger.error(log_message)
        elif severity == "critical":
            self.logger.critical(log_message)

        # 存储事件
        with self.lock:
            self.security_events.append(event)

            # 更新IP尝试次数
            if ip_address:
                self.ip_attempt_count[ip_address] = self.ip_attempt_count.get(ip_address, 0) + 1

                # 如果尝试次数过多，记录可能的暴力破解攻击
                if self.ip_attempt_count[ip_address] > 10:
                    self.logger.warning(
                        f"检测到可能的暴力破解攻击，IP: {ip_address}, 尝试次数: {self.ip_attempt_count[ip_address]}")

    def log_input_validation_failure(self, field_name: str, input_value: str,
                                     validation_type: str, ip_address: Optional[str] = None) -> None:
        """记录输入验证失败事件

        Args:
            field_name: 失败的字段名称
            input_value: 输入的值
            validation_type: 验证类型
            ip_address: 关联的IP地址
        """
        # 截断过长的输入值，避免日志过大
        truncated_value = str(input_value)
        if len(truncated_value) > 100:
            truncated_value = truncated_value[:100] + "..."

        details = {
            "field_name": field_name,
            "input_value": truncated_value,
            "validation_type": validation_type
        }

        self.log_security_event(
            event_type="input_validation_failure",
            details=details,
            severity="warning",
            ip_address=ip_address
        )

    def log_authentication_failure(self, username: str, reason: str,
                                   ip_address: Optional[str] = None) -> None:
        """记录认证失败事件

        Args:
            username: 尝试登录的用户名
            reason: 失败原因
            ip_address: 关联的IP地址
        """
        details = {
            "username": username,
            "reason": reason
        }

        self.log_security_event(
            event_type="authentication_failure",
            details=details,
            severity="warning",
            ip_address=ip_address
        )

    def log_vulnerability_detection(self, vulnerability_type: str, details: Dict[str, Any],
                                    severity: str = "error") -> None:
        """记录漏洞检测事件

        Args:
            vulnerability_type: 漏洞类型
            details: 漏洞详情
            severity: 严重程度
        """
        self.log_security_event(
            event_type="vulnerability_detected",
            details={"vulnerability_type": vulnerability_type, **details},
            severity=severity
        )

    def get_recent_events(self, count: int = 100, event_type: Optional[str] = None,
                          severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取最近的安全事件

        Args:
            count: 返回的事件数量
            event_type: 过滤的事件类型
            severity: 过滤的严重程度

        Returns:
            List[Dict[str, Any]]: 符合条件的事件列表
        """
        with self.lock:
            filtered_events = self.security_events

            if event_type:
                filtered_events = [e for e in filtered_events if e["event_type"] == event_type]

            if severity:
                filtered_events = [e for e in filtered_events if e["severity"] == severity]

            # 按时间倒序排序
            sorted_events = sorted(filtered_events, key=lambda x: x["timestamp"], reverse=True)

            return sorted_events[:count]

    def get_suspicious_ips(self, threshold: int = 5) -> List[Dict[str, Any]]:
        """获取可疑IP地址列表

        Args:
            threshold: 尝试次数阈值

        Returns:
            List[Dict[str, Any]]: 可疑IP信息列表
        """
        with self.lock:
            suspicious_ips = []

            for ip, count in self.ip_attempt_count.items():
                if count >= threshold:
                    # 获取该IP的所有事件
                    ip_events = [e for e in self.security_events if e.get("ip_address") == ip]

                    suspicious_ips.append({
                        "ip_address": ip,
                        "attempt_count": count,
                        "first_seen": min(e["timestamp"] for e in ip_events) if ip_events else 0,
                        "last_seen": max(e["timestamp"] for e in ip_events) if ip_events else 0,
                        "event_types": list(set(e["event_type"] for e in ip_events))
                    })

            # 按尝试次数倒序排序
            return sorted(suspicious_ips, key=lambda x: x["attempt_count"], reverse=True)