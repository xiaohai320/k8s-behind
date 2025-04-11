from functools import wraps
from flask import request, jsonify, g

def permission_required(role_name):
    """
    装饰器：限制只有拥有指定角色的用户才能访问
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 获取当前用户
            if not hasattr(g, 'current_user') or not g.current_user:
                return jsonify({"status": "error", "message": "Authentication required"}), 401

            # 检查用户是否拥有指定角色
            if not g.current_user.has_role(role_name):
                return jsonify({
                    "status": "error",
                    "message": f"Permission denied: Requires role '{role_name}'"
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
