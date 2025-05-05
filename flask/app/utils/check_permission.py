from functools import wraps

from flask import g

from app.commonutils.R import R
from app.models.rolePermissionModel import RolePermission


def permission_required(permission_name):
    """
    权限校验装饰器。
    :param permission_name: 需要校验的权限名称
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            # 获取用户的角色列表
            user_roles = g.current_user['user_roles'].split(',') if g.current_user['user_roles'] else []
            # 如果用户角色包含 'admin'，直接放行
            if 'admin' in user_roles:
                return f(*args, **kwargs)

            # 根据用户的角色查询所有权限
            all_permissions = set()
            for role_name in user_roles:
                role_permission = RolePermission.query.filter_by(role_name=role_name.strip()).first()
                if role_permission:
                    permissions = role_permission.permissions.split(',') if role_permission.permissions else []
                    all_permissions.update(permissions)
            print(permission_name)
            print(all_permissions)
            # 检查用户是否拥有指定权限
            if permission_name not in all_permissions:
                return R.error(code=233).set_message("Permission denied").to_json()

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# def permission_required(role_name):
#     """
#     装饰器：限制只有拥有指定角色的用户才能访问
#     """
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#
#
#             # 获取当前用户
#             if not hasattr(g, 'current_user') or not g.current_user:
#                 print(g.current_user['user_roles'])
#                 return jsonify({"status": "error", "message": "Authentication required"}), 401
#                 # 检查用户是否拥有指定角色
#             if 'user_roles' not in g.current_user or role_name not in g.current_user['user_roles']:
#                 return jsonify({
#                         "status": "error",
#                         "message": f"Permission denied: Requires role '{role_name}'"
#                     }), 403
#
#             return f(*args, **kwargs)
#         return decorated_function
#     return decorator
