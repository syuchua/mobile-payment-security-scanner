# -*- coding: utf-8 -*-
import logging
import os
import sys
import locale
from logging.handlers import RotatingFileHandler



# 设置默认编码为UTF-8
if sys.stdout.encoding != 'UTF-8':
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding != 'UTF-8':
    sys.stderr.reconfigure(encoding='utf-8')

# 设置系统默认编码
os.environ['PYTHONIOENCODING'] = 'utf-8'
# 设置区域设置
locale.setlocale(locale.LC_ALL, 'zh_CN.UTF-8' if locale.getpreferredencoding() == 'cp936' else '')

# 日志文件路径
LOG_FILE = "security_scan.log"
# 日志格式
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
# 日志级别
DEFAULT_LEVEL = logging.INFO
# 文件最大大小，超过后会创建新文件（5MB）
MAX_LOG_SIZE = 5 * 1024 * 1024
# 保留的日志文件数量
BACKUP_COUNT = 3


def get_logger(name):
    """
    获取指定名称的logger

    Args:
        name: logger名称，通常使用模块名称

    Returns:
        配置好的logger实例
    """
    logger = logging.getLogger(name)

    # 避免重复配置
    if logger.handlers:
        return logger

    logger.setLevel(DEFAULT_LEVEL)

    # 确保日志目录存在
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # 文件处理器
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(file_handler)

    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(console_handler)

    return logger


def get_class_logger(cls):
    """
    为类获取logger的便捷方法

    Args:
        cls: 类实例

    Returns:
        配置好的logger实例
    """
    module_name = cls.__class__.__module__
    class_name = cls.__class__.__name__
    return get_logger(f"{module_name}.{class_name}")