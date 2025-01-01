import os
import uuid
from flask import Blueprint, request, jsonify, current_app, g
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .captchaViews import verify_captcha
from ..commonutils.R import R
from ..extensions import store_login_status, remove_login_status
from ..models.userinfoModel import UserInfo
import jwt
from ..services.userinfoServices import verify_user, get_all_users, create_user, delete_user, update_user, \
    get_user_by_id, get_passhash_by_id
from ..utils.auth import token_required, ResponseCode, encode_auth_token, decode_auth_token

user_bp = Blueprint('userinfo', __name__)
@user_bp.route('/login', methods=['POST'])
def login():
    logindata = request.get_json()

    # 检查必要的字段是否存在
    if not logindata or 'account' not in logindata or 'password' not in logindata or 'captcha' not in logindata or 'captchaKey' not in logindata:
        return jsonify({'error': 'Missing required fields'}), 400
    if not verify_captcha(logindata.get('captcha'), logindata.get('captchaKey')):
        return R.error().set_message('Invalid Captcha or CaptchaKey').to_json()
    userinfo = verify_user(logindata.get('account'), logindata.get('password'))
    # # 生成新的JWT
    # token = encode_auth_token(userinfo.to_dict(), current_app.config['SECRET_KEY'])
    # 存储新的登录状态

    if userinfo == "forbidden":
        return R.error().set_message('此账户已被封禁，请联系管理员').to_json()
    if userinfo:
        token = encode_auth_token(userinfo.to_dict(), current_app.config['SECRET_KEY'])
        store_login_status(userinfo.to_dict()['id'],
                           jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['session_id'],
                           request.remote_addr)
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
@user_bp.route('/user/pageQueryMember', methods=['GET'])
@token_required
def get_users():
    try:
        # 获取分页参数，默认值为第一页，每页 10 条记录
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        # 获取查询参数
        name = request.args.get('name')
        account = request.args.get('account')
        role = request.args.get('role')
        is_enable = request.args.get('is_enable')
        # 构建查询对象
        query = UserInfo.query
        # 动态添加查询条件
        if name:
            query = query.filter(UserInfo.name.ilike(f'%{name}%'))
        if account:
            query = query.filter(UserInfo.account.ilike(f'%{account}%'))
        if role:
            query = query.filter(UserInfo.roles.ilike(f'%{role}%'))
        if is_enable:
            query = query.filter(UserInfo.is_enable.ilike(f'%{is_enable}%'))
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
        return R.ok().set_message('Users retrieved successfully').set_data({"items": response_data}).to_json()
    except Exception as e:
        current_app.logger.error(f"Error retrieving users: {e}")
        return R.error().set_message(f'An error occurred while retrieving users:{e}').to_json()

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
@user_bp.route('/user/delete/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user_route(user_id):
    try:
        # 调用 delete_user 函数删除用户
        deleted = delete_user(user_id)
        if deleted:
            return R.ok().set_message('User deleted successfully').to_json()
        else:
            return R.error().set_message('User not found or deletion failed').set_code(ResponseCode.NOT_FOUND).to_json()
    except Exception as e:
        current_app.logger.error(f"Error in delete_user_route: {e}")
        return R.error().set_message(f'An error occurred while deleting the user:{e}').to_json()
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
def update_password_route():
    try:
        # 解析 JSON 请求体中的参数
        data = request.get_json()
        user_id = data.get('id')
        old_password = data.get('oldPass')
        new_password = data.get('newPass')
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
def logout():
    try:
        user_info = g.current_user
        user_id = user_info['user_id']
        session_id = user_info['session_id']
        # 移除 Redis 中的会话信息
        remove_login_status(user_id)
        # 打印调试信息
        current_app.logger.info(f"User {user_id} logged out successfully.")
        return R.ok().set_message('Logout successful').to_json()
    except Exception as e:
        current_app.logger.error(f"Error during logout: {str(e)}")
        return R.error().set_message(str(e)).set_code(ResponseCode.INTERNAL_ERROR).to_json()