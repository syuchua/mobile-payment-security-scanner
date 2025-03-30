# 向 src/config/__init__.py 中添加以下代码

def get_system_version(url):
    """根据URL确定系统版本"""
    if ':5000' in url:
        return 'basic'
    elif ':5001' in url:
        return 'secure'
    elif ':5002' in url:
        return 'enhanced'
    return 'unknown'

def get_endpoints_for_version(version):
    """获取特定版本系统的端点"""
    if version == 'basic':
        return ['/search', '/feedback', '/profile', '/api/payment', '/api/user_data']
    elif version == 'secure':
        return ['/secure/search', '/secure/feedback', '/secure/profile', '/api/v2/payment']
    elif version == 'enhanced':
        return ['/v2/search', '/v2/feedback', '/v2/profile', '/api/v3/payment']
    return ['/search', '/feedback', '/profile', '/api/payment']  # 默认