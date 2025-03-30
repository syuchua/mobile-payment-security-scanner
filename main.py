# main.py
import sys
import logging
import os
import time
import argparse
from datetime import datetime
from urllib.parse import urlparse
from src.config.config_manager import ConfigManager
from src.core.scan_manager import ScanManager
from src.protection.input_sanitizer import InputSanitizer
from src.protection.security_monitor import SecurityMonitor
from src.reporting.report_generator import ReportGenerator
from src.reporting.console_reporter import ConsoleReporter
from src.reporting.exporters.exporter_factory import ExporterFactory
from src.rules.rule_updater import RuleUpdater
from src.core.mock_interceptor import MockNetworkInterceptor

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_scan.log"),
        logging.StreamHandler(sys.stdout)
    ]
)


def is_https(url):
    """检查URL是否使用HTTPS协议

    Args:
        url: 目标URL

    Returns:
        bool: 如果是HTTPS则返回True，否则返回False
    """
    parsed_url = urlparse(url)
    return parsed_url.scheme.lower() == 'https'


def get_port_from_url(url):
    """从URL中提取端口号

    Args:
        url: 目标URL

    Returns:
        str: 端口号，如果未指定则返回默认值
    """
    parsed_url = urlparse(url)
    if parsed_url.port:
        return str(parsed_url.port)
    elif parsed_url.scheme.lower() == 'https':
        return '443'
    else:
        return '80'


def export_report(report, config_manager):
    """
    根据配置导出报告

    Args:
        report: 报告数据
        config_manager: 配置管理器
    """
    # 获取报告配置
    report_config = config_manager.get_report_config()
    formats = report_config.get('export_formats', ['pdf', 'html'])
    report_dir = report_config.get('report_dir', 'reports')

    # 创建报告目录
    os.makedirs(report_dir, exist_ok=True)

    # 生成报告文件名（基于时间戳）
    timestamp = report["scan_info"]["scan_date"].replace(":", "-").replace(" ", "_")
    base_filename = f"security_report_{timestamp}"

    # 导出每种格式
    for format_type in formats:
        try:
            # 创建导出器
            exporter = ExporterFactory.create_exporter(format_type)

            # 设置输出路径
            output_path = os.path.join(report_dir, f"{base_filename}.{format_type}")

            # 导出报告
            print(f"正在导出 {format_type.upper()} 报告...")
            exporter.export(report, output_path)
            print(f"{format_type.upper()} 报告已生成: {output_path}")

        except Exception as e:
            print(f"导出 {format_type.upper()} 报告时出错: {e}")

    print(f"\n报告文件位于: {os.path.abspath(report_dir)}")


def check_rule_updates(config_manager):
    """
    检查并更新规则

    Args:
        config_manager: 配置管理器

    Returns:
        Dict[str, Any]: 更新结果
    """
    # 获取规则更新配置
    update_config = config_manager.config.get('rule_updates', {})

    if not update_config.get('enable_auto_update', True):
        print("规则自动更新已禁用")
        return {"status": "disabled"}

    # 创建规则更新器
    rule_updater = RuleUpdater(
        rule_base_dir=update_config.get('rule_base_dir', 'rules'),
        update_url=update_config.get('update_url', 'https://security-rules.example.com/api/latest')
    )

    print("正在检查规则更新...")
    try:
        result = rule_updater.update_rules()

        if result['status'] == 'updated':
            print(f"规则已更新至版本 {result['version']}")
            print(f"已更新规则类型: {', '.join(result['rules_updated'])}")
        elif result['status'] == 'up_to_date':
            print("规则已是最新版本")
        else:
            print(f"规则更新失败: {result.get('message', '未知错误')}")

        return result
    except Exception as e:
        print(f"规则更新失败: {str(e)}")
        return {"status": "error", "message": str(e)}


def main():
    print("======= 移动支付系统安全漏洞扫描器 =======")

    # 创建独立解析器处理--mock参数
    parser = argparse.ArgumentParser(description='移动支付系统安全漏洞扫描器')
    parser.add_argument('--mock', action='store_true', help='使用模拟模式，不发送实际网络请求')
    parser.add_argument('-u', '--target', dest='target_url', help='目标URL')
    parser.add_argument('scan', nargs='?', help='扫描命令')

    # 先解析mock参数
    args, remaining = parser.parse_known_args()

    # 创建配置管理器并传入剩余参数
    sys.argv[1:] = remaining
    config_manager = ConfigManager()
    config_manager.parse_args()

    # 将target_url参数传给config_manager
    if args.target_url:
        config_manager.set_target_url(args.target_url)

    # 如果指定了--mock参数，启用模拟模式
    if args.mock:
        if 'general' not in config_manager.config:
            config_manager.config['general'] = {}
        config_manager.config['general']['mock_mode'] = True
        print("已启用模拟模式，将不会发送实际网络请求")
        # 启用全局模拟拦截
        from src.core.mock_system import MockSystem
        mock_interceptor = MockSystem.enable_global_mock_mode()
    else:
        mock_interceptor = None

    # 检查规则更新
    check_rule_updates(config_manager)

    # 创建安全监控器
    security_monitor = SecurityMonitor()

    target_url = config_manager.get_target_url() or "http://localhost:5000"
    print(f"目标系统: {target_url}")

    # 检查URL协议与端口是否匹配
    target_port = get_port_from_url(target_url)
    is_secure = is_https(target_url)

    # 根据端口号输出信息
    if target_port == '5000':
        print("正在扫描基础版支付系统 (端口5000)")
        if is_secure:
            print("警告: 基础版系统使用HTTP协议，但您使用的是HTTPS URL。正在切换到HTTP...")
            target_url = target_url.replace('https://', 'http://')
            config_manager.set_target_url(target_url)
    elif target_port == '5001':
        print("正在扫描安全版支付系统 (端口5001)")
        if not is_secure:
            print("警告: 安全版系统使用HTTPS协议，但您使用的是HTTP URL。正在切换到HTTPS...")
            target_url = target_url.replace('http://', 'https://')
            config_manager.set_target_url(target_url)
    elif target_port == '5002':
        print("正在扫描增强版支付系统 (端口5002)")
        if not is_secure:
            print("警告: 增强版系统使用HTTPS协议，但您使用的是HTTP URL。正在切换到HTTPS...")
            target_url = target_url.replace('http://', 'https://')
            config_manager.set_target_url(target_url)

    print("正在初始化扫描器...")

    # 配置跳过SSL验证（用于自签名证书）
    if is_https(target_url):
        if 'general' not in config_manager.config:
            config_manager.config['general'] = {}
        config_manager.config['general']['verify_ssl'] = False
        print("注意: 已禁用SSL证书验证，适用于使用自签名证书的测试环境")

    # 修改main.py中的相关代码段
    if mock_interceptor:
        # 将拦截器设置到config_manager中，而不是直接传给ScanManager
        config_manager.config['general']['interceptor'] = mock_interceptor
        scan_manager = ScanManager(config_manager)
        print("正在使用全局模拟网络拦截器...")
    else:
        # 使用默认拦截器
        scan_manager = ScanManager(config_manager)

    # 创建输入净化器
    sanitizer = InputSanitizer()

    try:
        # 示例：模拟一个安全的支付请求
        payment_data = {
            "amount": "100.50",
            "card_number": "4111-1111-1111-1111",
            "description": "Test payment",
            "user_id": "user123"
        }

        # 净化输入数据
        clean_data = sanitizer.sanitize_payment_data(payment_data)
        print(f"原始数据: {payment_data}")
        print(f"净化后数据: {clean_data}")

        # 根据不同端口选择不同的测试端点
        if target_port == '5000':
            test_endpoint = '/api/payment'
        elif target_port == '5001':
            test_endpoint = '/api/v2/payment'
        elif target_port == '5002':
            test_endpoint = '/api/v3/payment'
        else:
            test_endpoint = '/api/payment'

        # 发送一个测试请求
        print(f"\n发送测试请求到 {test_endpoint}...")
        try:
            response = scan_manager.interceptor.intercept_request(
                method='POST',
                endpoint=test_endpoint,
                json=clean_data,
                headers={'Authorization': 'Bearer test_token'},
                timeout=10  # 添加超时设置
            )
            print(f"测试请求完成，响应状态码: {response.status_code}")
        except Exception as e:
            print(f"测试请求失败: {e}")
            print("尝试继续扫描...")

        # 运行所有漏洞扫描器
        print("\n开始进行漏洞扫描...")
        all_vulnerabilities = scan_manager.run_all_scanners()

        # 生成详细报告
        print("\n正在生成详细报告...")
        report_generator = ReportGenerator(target_url)
        report = report_generator.generate_report(all_vulnerabilities)

        # 在控制台显示报告
        console_reporter = ConsoleReporter()
        console_reporter.display_report(report)

        # 导出报告
        export_report(report, config_manager)

        # 输出安全监控报告
        security_monitoring_config = config_manager.config.get('security_monitoring', {})
        ip_threshold = security_monitoring_config.get('ip_threshold', 5)
        alert_on_suspicious = security_monitoring_config.get('alert_on_suspicious', True)

        suspicious_ips = security_monitor.get_suspicious_ips(threshold=ip_threshold)

        if suspicious_ips and alert_on_suspicious:
            print("\n检测到可疑IP活动:")
            for ip_info in suspicious_ips:
                print(f"IP: {ip_info['ip_address']}, 尝试次数: {ip_info['attempt_count']}")
                print(f"事件类型: {', '.join(ip_info['event_types'])}")
                print("---")

        # 输出安全事件统计
        recent_events = security_monitor.get_recent_events(count=10)
        if recent_events:
            print("\n最近10条安全事件:")
            for event in recent_events:
                print(f"时间: {event['timestamp']}, 类型: {event['event_type']}, 严重性: {event['severity']}")

    except Exception as e:
        print(f"扫描过程中发生错误: {e}")
        logging.error(f"扫描过程中发生错误: {e}", exc_info=True)
        print("\n扫描中断。尝试以下操作解决问题:")
        print("1. 确认目标系统正在运行")
        print("2. 检查端口是否正确")
        print("3. 使用正确的协议（HTTP或HTTPS）")
        print("4. 检查网络连接是否正常")


if __name__ == "__main__":
    main()