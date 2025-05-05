from datetime import datetime
from zoneinfo import ZoneInfo

from flask import request, Blueprint, current_app

from app import db
from app.commonutils.R import R
from app.models.rolePermissionModel import RolePermission
from app.utils.auth import token_required
from app.utils.check_permission import permission_required
from app.utils.operation_record import operation_record

role_bp = Blueprint('role_bp', __name__)

@role_bp.route('/roles/pageQuery/<int:page>/<int:per_page>', methods=['GET'])
@token_required
@permission_required('role_query')
def get_roles_paginated(page, per_page):
    """
    分页查询角色及其权限。
    :param page: 当前页码
    :param per_page: 每页记录数
    """
    try:
        # 获取查询参数
        role_name = request.args.get('role_name')  # 根据角色名称过滤
        permission = request.args.get('permission')  # 根据特定权限过滤

        # 构建查询对象
        query = RolePermission.query

        # 动态添加查询条件
        if role_name:
            query = query.filter(RolePermission.role_name.ilike(f'%{role_name}%'))
        if permission:
            query = query.filter(RolePermission.permissions.ilike(f'%{permission}%'))

        # 执行分页查询
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        # 构建响应数据
        roles = [role.to_dict() for role in pagination.items]
        response_data = {
            'items': roles,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': pagination.page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }

        return R.ok().set_data(response_data).to_json()

    except Exception as e:
        current_app.logger.error(f"Error retrieving roles: {e}")
        return R.error().set_message(str(e)).to_json()


@role_bp.route('/roles', methods=['POST'])
@token_required
@permission_required('role_add')
@operation_record(description='添加角色')

def add_role():
    """
    添加新角色及其权限。
    """
    data = request.get_json()
    role_name = data.get('role_name')
    permissions = data.get('permissions')

    if not role_name or not permissions:
        return R.error().set_message('Missing role_name or permissions').to_json()

    # 检查角色是否已存在
    if RolePermission.query.filter_by(role_name=role_name).first():
        return R.error().set_message('Role already exists').to_json()

    # 创建新角色
    new_role = RolePermission(
        role_name=role_name,
        permissions=permissions  # 将权限列表转为逗号分隔的字符串
    )
    db.session.add(new_role)
    db.session.commit()

    return R.ok().set_message('Role created successfully').set_data(new_role.to_dict()).to_json()


@role_bp.route('/roles/<string:role_name>', methods=['PUT'])
@token_required
@permission_required('role_update')
@operation_record(description='修改角色')
def update_role(role_name):
    """
    修改角色的权限。
    """
    role = RolePermission.query.filter_by(role_name=role_name).first()
    if not role:
        return R.error().set_message('Role not found').to_json()

    data = request.get_json()
    new_permissions = data.get('permissions')

    if not new_permissions:
        return R.error().set_message('Missing permissions').to_json()

    # 更新权限
    role.permissions = new_permissions
    role.updated_at = datetime.now(ZoneInfo('Asia/Shanghai'))
    db.session.commit()

    return R.ok().set_message('Role updated successfully').set_data(role.to_dict()).to_json()


@role_bp.route('/roles/<string:role_name>', methods=['DELETE'])
@token_required
@permission_required('role_delete')
@operation_record(description='删除角色')
def delete_role(role_name):
    """
    删除角色及其权限。
    """
    role = RolePermission.query.filter_by(role_name=role_name).first()
    if not role:
        return R.error().set_message('Role not found').to_json()

    # 删除角色
    db.session.delete(role)
    db.session.commit()

    return R.ok().set_message('Role deleted successfully').to_json()

