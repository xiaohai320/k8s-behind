# app/extensions.py
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import json, current_app, request
from redis import ConnectionPool, Redis


def init_redis_pool(app):
    """初始化Redis连接池"""
    global redis_pool
    redis_pool = ConnectionPool(
        host=app.config['REDIS_HOST'],
        port=app.config['REDIS_PORT'],
        db=app.config['REDIS_DB'],
        password=app.config['REDIS_PASSWORD']
    )
def get_redis_client():
    """根据当前配置返回一个Redis客户端实例"""
    return Redis(connection_pool=redis_pool)
def store_login_status(user_id, session_id, ip_address):
    redis_client = get_redis_client()
    key = f"user_session:{user_id}"
    value = {'session_id': session_id, 'ip_address': ip_address}
    redis_client.setex(key,7200, json.dumps(value))
def get_client_ip():
    # 如果使用了反向代理，优先从 X-Forwarded-For 获取真实IP
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr


def remove_captcha(ip_address):
    redis_client = get_redis_client()
    pattern = f"captcha:{ip_address}:*"
    cursor = 0
    while True:
        cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=100)
        if keys:
            redis_client.delete(*keys)
        if cursor == 0:
            break
def add_jti_to_blacklist(jti, exp_timestamp):
    redis_client = get_redis_client()
    now = datetime.now(ZoneInfo('Asia/Shanghai'))

    # 假设 exp_timestamp 是一个整数（Unix 时间戳）
    if isinstance(exp_timestamp, int):
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=ZoneInfo('Asia/Shanghai'))
    else:
        exp_datetime = exp_timestamp  # 确保是带时区信息的 datetime 对象

    ttl = int((exp_datetime - now).total_seconds())
    if ttl > 0:
        redis_client.setex(f"blacklist:jti:{jti}", ttl, 'revoked')
def check_jti_in_blacklist(jti):
    redis_client = get_redis_client()
    return bool(redis_client.get(f"blacklist:jti:{jti}"))
def check_login_status(user_id, session_id):
    redis_client = get_redis_client()
    key = f"user_session:{user_id}"
    stored_data = redis_client.get(key)
    if stored_data:
        stored_data = json.loads(stored_data)

        return stored_data.get('session_id') == session_id
    return False
def remove_login_status(user_id):
    redis_client = get_redis_client()
    key = f"user_session:{user_id}"
    if redis_client.exists(key):
        redis_client.delete(key)
        current_app.logger.info(f"Removed login status for user_id: {user_id}")
    else:
        current_app.logger.warning(f"No stored session found for user_id: {user_id}")