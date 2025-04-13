import os
import uuid
from flask import Blueprint, request, jsonify, g

from werkzeug.utils import secure_filename
from .captchaViews import verify_captcha
from ..extensions import store_login_status, remove_login_status
import jwt
from ..services.userinfoServices import *
from ..utils.auth import token_required, ResponseCode, encode_auth_token, decode_auth_token
from ..utils.check_permission import permission_required
from ..utils.operation_record import operation_record, log_operation
user_bp = Blueprint('userinfo', __name__)
@user_bp.route('/login', methods=['POST'])
def login():
    logindata = request.get_json()
    # 检查必要的字段是否存在
    if not logindata or 'account' not in logindata or 'password' not in logindata or 'captcha' not in logindata or 'captchaKey' not in logindata:
        return R.error().set_message('Missing required fields').to_json()
    if not verify_captcha(logindata.get('captcha'), logindata.get('captchaKey')):
        return R.error().set_message('Invalid Captcha or CaptchaKey').to_json()
    userinfo = verify_user(logindata.get('account'), logindata.get('password'))
    if userinfo == "forbidden":
        return R.error().set_message('此账户已被封禁，请联系管理员').to_json()
    if userinfo:
        token = encode_auth_token(userinfo.to_dict(), current_app.config['SECRET_KEY'])
        store_login_status(userinfo.to_dict()['id'],
                           jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['session_id'],
                           request.remote_addr)
        log_operation(logindata.get('account'), "登录", {"data":{"ip":request.remote_addr}})
        return R.ok().set_message('Login successful').set_data({'token': token}).to_json()
    else:
        return R.error().set_message('Invalid username or password').set_code(ResponseCode.UNAUTHORIZED).to_json()
@user_bp.route('/user/info', methods=['GET'])
@token_required  # 假设你有一个装饰器来检查 token 是否有效
def get_user_info():
    try:
        user_id=g.current_user["user_id"]
        user_info = get_user_by_id(user_id)
        if user_info:
            return R.ok().set_message('User info retrieved successfully').set_data({"items": user_info}).to_json()
        else:
            return R.error().set_message('User info not found or Invalid token').to_json()
    except Exception as e:
        current_app.logger.error(f"Error in get_user_info: {e}")
        return R.error().set_message(f"Error in get_user_info: {e}").to_json()
@user_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'account' not in data or 'password' not in data:
        return R.error().set_message("Account and password are required").set_code(ResponseCode.UNAUTHORIZED).to_json()
    account = data['account']
    password = data['password']
    # 调用注册逻辑
    userinfo,error= create_user(account, password)
    if userinfo:
        return R.ok().set_message("Registration successful").to_json()
    else:
        return R.error().set_message( error or "Registration Failed").to_json()
@user_bp.route('/user/selectById', methods=['POST'])
@token_required
def select_by_id():
    try:
        # 解析 JSON 请求体中的 user_id 参数
        data = request.get_json()
        user_id = data.get('id')
        if not user_id:
            return R.error().set_message('Missing user_id parameter').set_code(1000).to_json()
        # 调用 get_user_by_id 函数获取用户信息
        user_data = get_user_by_id(user_id)

        if user_data:
            return R.ok().set_message('User retrieved successfully').set_data({"items": user_data}).to_json()
        else:
            return R.error().set_message('User not found').set_code(ResponseCode.NOT_FOUND).to_json()
    except Exception as e:
        current_app.logger.error(f"Error in selectById endpoint: {e}")
        return R.error().set_message(f"Error in selectById endpoint: {e}").to_json()
@user_bp.route('/user/pageQueryMember/<int:page>/<int:per_page>', methods=['GET'])
@token_required
def get_users(page, per_page):
    try:
        # 获取分页参数，默认值为第一页，每页 10 条记录
        # page = int(request.args.get('page', 1))
        # per_page = int(request.args.get('per_page', 10))
        # 获取查询参数
        name = request.args.get('name')
        role = request.args.get('role')
        is_enable = request.args.get('is_enable')
        phone = request.args.get('phone')
        # 构建查询对象
        query = UserInfo.query
        # 动态添加查询条件
        if name:
            query = query.filter((UserInfo.name.ilike(f'%{name}%')) | (UserInfo.account.ilike(f'%{name}%')))

        if role:
            query = query.filter(UserInfo.roles.ilike(f'%{role}%'))
        if is_enable:
            query = query.filter(UserInfo.is_enable.ilike(f'%{is_enable}%'))
        if phone:
            query = query.filter(UserInfo.phone.ilike(f'%{phone}%'))
        # 执行分页查询
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        # 构建响应数据
        users = [user.to_dict() for user in pagination.items]
        response_data = {
            'items': users,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': pagination.page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
        return R.ok().set_message('Users retrieved successfully').set_data(response_data).to_json()
    except Exception as e:
        current_app.logger.error(f"Error retrieving users: {e}")
        return R.error().set_message(f'An error occurred while retrieving users:{e}').to_json()

@user_bp.route('/user/enableOrDisableMember/<int:user_id>', methods=['POST'])
@token_required
@operation_record(description='启用或禁用用户')
@permission_required('admin')
def enable_or_disable_member(user_id):
    try:
        # 解析 JSON 请求体中的 isEnable 参数
        data = request.get_json()
        is_enable = data.get('isEnable')
        if is_enable is None:
            return R.error().set_message('Missing isEnable parameter').set_code(1000).to_json()
        # 调用 update_user_status 函数更新用户状态
        result = update_isEnable_status(user_id, is_enable)
        if result:
            # action = 'enabled' if is_enable else 'disabled'
            return R.ok().to_json()
        else:
            return R.error().set_message('Failed to update user status').to_json()
    except Exception as e:
        current_app.logger.error(f"Error in enableOrDisableMember endpoint: {e}")
        return R.error().set_message(f"Error in enableOrDisableMember endpoint: {e}").to_json()
@user_bp.route('/user/update', methods=['PUT'])
@token_required

def update_user_route():
    try:
        # 解析 JSON 请求体中的参数
        data = request.get_json()
        user_id = data.get('id')
        name = data.get('name')
        account = data.get('account')
        # password = data.get('password')
        roles = data.get('roles')
        phone = data.get('phone')
        avatar = data.get('avatar')
        posts=data.get('posts')
        department=data.get('department')
        if not user_id:
            return R.error().set_message('Missing user_id parameter').set_code(ResponseCode.BAD_REQUEST).to_json()
        # 检查是否有对 roles 的修改，并确保当前用户是管理员
        sensitive_fields = [roles, account, posts, department]
        if str(user_id) != str(g.current_user['user_id']) or g.current_user['user_roles'] == 'admin':
            return R.error().set_message('Invalid modify!').to_json()
        if any(field is not None for field in sensitive_fields) and g.current_user['user_roles'] != 'admin':
            return R.error().set_message('Only administrators can modify sensitive fields').to_json()
        # 调用 update_user 函数更新用户信息
        updated_user = update_user(user_id, name, account, None, roles, phone,avatar,posts,department)
        if updated_user:
            return R.ok().set_message('User updated successfully').set_data({"items": updated_user}).to_json()
        else:
            return R.error().set_message('User not found or update failed').to_json()
    except Exception as e:
        current_app.logger.error(f"Error in update_user_route: {e}")
        return  R.error().set_message( 'An error occurred while updating the user').to_json()
@user_bp.route('/user/delete', methods=['DELETE'])
@token_required
@permission_required('admin')
@operation_record(description='删除用户')
def delete_user_route():
    try:
        # 获取请求中的用户ID列表
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        if not user_ids:
            return R.error().set_message('No user IDs provided').to_json()

        # 调用 delete_user 函数删除用户
        deleted = delete_user(user_ids)
        if deleted:
            return R.ok().set_message('Users deleted successfully').to_json()
        else:
            return R.error().set_message('Users not found or deletion failed').to_json()

    except Exception as e:
        current_app.logger.error(f"Error in delete_user_route: {e}")
        return R.error().set_message(f'An error occurred while deleting the users: {e}').to_json()

UPLOAD_FOLDER = '../../static/img/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
@user_bp.route('/uploadAvatar', methods=['POST'])
@token_required
def upload_avatar():
    try:
        if 'image' not in request.files:
            return R.error().set_message('No file part').to_json()
        file = request.files['image']
        if file.filename == '':
            return R.error().set_message('No selected file').to_json()
        if file and allowed_file(file.filename):
            safe_filename = secure_filename(file.filename)
            name, ext = os.path.splitext(safe_filename)
            # 使用 uuid4() 生成一个随机的 UUID，并转换为字符串形式
            unique_name = f"{name}_{uuid.uuid4().hex}{ext}"
            filepath = os.path.join(current_app.static_folder, 'img', unique_name)  # 使用 Flask 的静态文件夹路径
            os.makedirs(os.path.dirname(filepath), exist_ok=True)  # 确保目录存在
            file.save(filepath)
            # 构建访问 URL
            avatar_url = f"http://localhost:5000/static/img/{unique_name}"
            # 更新用户信息中的头像字段
            # user_id = g.current_user['user_id']
            # update_user(user_id, avatar=avatar_url)
            return R.ok().set_data({'relativePath': avatar_url}).to_json()
        else:
            return R.error().set_message('Invalid file type').to_json()
    except Exception as e:
        current_app.logger.error(f"Error in upload_avatar: {e}")
        return R.error().set_message('An error occurred while uploading the avatar').to_json()
@user_bp.route('/user/updatePassword', methods=['PUT'])
@token_required
@operation_record('updatePassword')
def update_password_route():
    try:
        # 解析 JSON 请求体中的参数
        data = request.get_json()
        user_id = data.get('id')
        old_password = data.get('oldPass')
        new_password = data.get('newPass')
        print("old"+old_password)
        print("new"+new_password)
        if str(user_id) != str(g.current_user['user_id']) or g.current_user['user_roles'] == 'admin':
            return R.error().set_message('Invalid modify!').to_json()
        if not data  or 'oldPass' not in data  or 'newPass' not in data or 'captcha' not in data or 'captchaKey' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        if not verify_captcha(data.get('captcha'), data.get('captchaKey')):
            return R.error().set_message('Invalid Captcha or CaptchaKey').to_json()
        # 检查用户是否为当前登录用户
        if str(user_id) != str(g.current_user['user_id']):
            return R.error().set_message('Invalid modify!').to_json()
        # 验证旧密码是否正确（假设有一个 get_user_by_id 函数）
        passhash = get_passhash_by_id(user_id)
        # print("hash:"+passhash)
        if not passhash or not check_password_hash(passhash, old_password):
            return R.error().set_message('Incorrect old password').to_json()
        # 更新密码（假设有一个 update_user_password 函数）
        updated = update_user(user_id,None,None, new_password)
        if updated:
            return R.ok().set_message('Password updated successfully').to_json()
        else:
            return R.error().set_message('User not found or update failed').to_json()

    except Exception as e:
        current_app.logger.error(f"Error in update_password_route: {e}")
        return R.error().set_message('An error occurred while updating the password').to_json()
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@user_bp.route('/logout', methods=['POST'])
@token_required
@operation_record(description='用户登出')
def logout():
    try:
        user_info = g.current_user
        user_id = user_info['user_id']
        session_id = user_info['session_id']
        # 移除 Redis 中的会话信息
        remove_login_status(user_id)
        # 打印调试信息
        current_app.logger.info(f"User {user_id} logged out successfully.")
        log_operation(user_info['user_account'], "下线",None)
        return R.ok().set_message('Logout successful').to_json()
    except Exception as e:
        current_app.logger.error(f"Error during logout: {str(e)}")
        return R.error().set_message(str(e)).set_code(ResponseCode.INTERNAL_ERROR).to_json()
@user_bp.route('/batch-reset-password', methods=['POST'])
@token_required
@permission_required('admin')
@operation_record(description='批量重置密码')
def batch_reset_password():
    data = request.get_json()
    print(data)
    if not data or 'user_ids' not in data or not isinstance(data['user_ids'], list):
        return R.error().set_message("缺少必要参数或参数格式错误").set_code(ResponseCode.BAD_REQUEST).to_json()

    user_ids = data['user_ids']
    if not user_ids:
        return R.error().set_message("未选择任何用户").set_code(ResponseCode.BAD_REQUEST).to_json()
    if batch_reset_password_service(user_ids):
        return R.ok().set_message("批量重置密码成功").to_json()
    else:
        return R.error().set_message("批量重置密码失败").to_json()
@user_bp.route('/adduser', methods=['POST'])
@token_required
@permission_required('admin')
@operation_record(description='添加用户')
def adduser():
    data = request.get_json()
    if not data or not all(key in data for key in ['account', 'department', 'posts', 'roles', 'phone']):
        return R.error().set_message("缺少必要参数").set_code(ResponseCode.BAD_REQUEST).to_json()

    account = data['account']
    department = data['department']
    posts = data['posts']
    roles = data['roles']
    phone = data['phone']
    is_enable = data.get('is_enable', True)  # 默认启用

    # 检查账户是否已存在
    existing_user = UserInfo.query.filter_by(account=account).first()
    if existing_user:
        return R.error().set_message("账户已存在").to_json()

    # 创建新用户
    new_user = UserInfo(
        account=account,
        password_hash=generate_password_hash("Admin@123"),  # 统一密码
        department=department,
        posts=posts,
        roles=roles,
        phone=phone,
        is_enable=is_enable,
        create_at=datetime.now(ZoneInfo('Asia/Shanghai')),
        update_at=datetime.now(ZoneInfo('Asia/Shanghai'))
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return R.ok().set_message("用户添加成功").to_json()
    except Exception as e:
        db.session.rollback()
        return R.error().set_message(f"用户添加失败: {str(e)}").to_json()
@user_bp.route('/user/updateRole', methods=['PUT'])
@token_required
@operation_record(description='修改用户角色')
@permission_required('admin')
def update_user_role_route():
    try:
        # 解析 JSON 请求体中的参数
        data = request.get_json()
        user_id = data.get('id')
        roles = data.get('roles')
        if not user_id or roles is None:
            return R.error().set_message('Missing user_id or roles parameter').set_code(ResponseCode.BAD_REQUEST).to_json()
        # 检查是否有对 roles 的修改，并确保当前用户是管理员
        if g.current_user['user_roles'] != 'admin':
            return R.error().set_message('Only administrators can modify roles').to_json()
        # 调用 update_user_role 函数更新用户角色
        updated_user = update_user_role(user_id, roles)
        if updated_user:
            return R.ok().set_message('User role updated successfully').set_data({"items": updated_user}).to_json()
        else:
            return R.error().set_message('User not found or update failed').to_json()

    except Exception as e:
        current_app.logger.error(f"Error in update_user_role_route: {e}")
        return R.error().set_message('An error occurred while updating the user role').to_json()
