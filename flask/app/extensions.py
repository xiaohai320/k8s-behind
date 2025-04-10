# app/extensions.py
from flask import json, current_app
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

def check_login_status(user_id, session_id):
    redis_client = get_redis_client()
    key = f"user_session:{user_id}"
    stored_data = redis_client.get(key)
    if stored_data:
        stored_data = json.loads(stored_data)
        # print("stored_data",stored_data)
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