from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

from flask import request, current_app, g

from .. import db
from ..models.useroperationlog import UserOperationLog

def operation_record(description=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # 执行原始视图函数
                response = f(*args, **kwargs)
                # 如果视图函数返回了元组 (response, status_code)，则取第一个元素作为实际响应对象
                if isinstance(response, tuple) and len(response) >= 2:
                    actual_response, status_code = response[0], response[1]
                else:
                    actual_response, status_code = response, 200
                # 只有当状态码表示成功时才记录操作
                if 200 <= status_code < 300:
                    user_account = g.current_user["user_account"]
                    operation = description or f.__name__
                    details = {
                        'method': request.method,
                        'path': request.path,
                        'query_string': request.query_string.decode(),
                        'data': request.get_json(silent=True) or {}
                    }
                    print(details)
                    # 记录操作日志
                    log_operation(user_account, operation, details)
                return response
            except Exception as e:
                print(e)
                # 捕获所有异常，确保即使发生错误也不会影响原有逻辑
                raise "e"
        return decorated_function
    return decorator
def log_operation(user_account,  operation, details):
    with current_app.app_context():
        new_log = UserOperationLog(
            user_account=user_account,
            operation=operation,
            timestamp=datetime.now(ZoneInfo("Asia/Shanghai")),  # 使用 UTC 时间
            details=details
        )
        db.session.add(new_log)
        db.session.commit()