import uuid

from flask import Flask, request, jsonify, g, current_app
import jwt
from functools import wraps
from datetime import datetime, timedelta

from werkzeug.exceptions import Unauthorized

from app.commonutils.R import R
from app.commonutils.ResultCode import ResponseCode
from app.extensions import check_login_status
def encode_auth_token(user_info, secret_key, device_id=None):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=6),
            'iat': datetime.utcnow(),
            'user_account': user_info['account'],  # 使用 account 作为 sub
            'user_id': user_info['id'],   # 添加 user_id 到 payload
            'user_roles': user_info['roles'],  # 添加 user_roles 到 payload
            'session_id': str(uuid.uuid4())   # 唯一会话ID
        }
        return jwt.encode(payload, secret_key, algorithm='HS256')
    except Exception as e:
        return str(e)
def decode_auth_token(auth_token):
    """解码认证令牌"""
    try:
        # 检查 SECRET_KEY 是否已设置
        if not current_app.config.get('SECRET_KEY'):
            raise AuthError('SECRET_KEY is not set', 500)
        # 解码 JWT
        payload = jwt.decode(auth_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        # 验证 JWT 的内容
        if 'user_account' not in payload or 'user_id' not in payload or 'session_id' not in payload:
            raise jwt.InvalidTokenError
        extracted_payload = {
            'user_account': payload.get('user_account'),
            'user_id': payload.get('user_id'),
            'user_roles': payload.get('user_roles'),
            'session_id': payload.get('session_id')
        }

        # 日志记录成功解码
        current_app.logger.info("Token decoded successfully.")
        return extracted_payload  # 返回用户 ID 或其他标识符
    except jwt.ExpiredSignatureError:
        current_app.logger.warning("Token expired.")
        raise AuthError('Token expired. Please log in again.', 401)
    except jwt.InvalidTokenError as e:
        current_app.logger.warning(f"Invalid token: {str(e)}")
        raise AuthError('Invalid token. Please log in again.', 401)
    except Exception as e:
        current_app.logger.error(f"Unexpected error during token decoding: {str(e)}")
        raise Unauthorized(description='An unexpected error occurred during token decoding.')
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'X-Token' in request.headers:
            token = request.headers['X-Token']
        if not token:
            return R.error().set_message('Token is missing!').set_code(ResponseCode.UNAUTHORIZED).to_json()
        try:
            user_info = decode_auth_token(token)
            user_id = user_info['user_id']
            session_id = user_info['session_id']
            # 检查当前会话是否是最新会话
            if not check_login_status(user_id, session_id):
                return R.ok().set_message('You have been logged in from another device. Please log in again.').set_code(ResponseCode.OTHER_CLIENT_LOGGED_IN).to_json()
            g.current_user = user_info  # 将当前用户信息附加到全局变量g上
        except Exception as e:
            return R.ok().set_code(ResponseCode.INVALID_CREDENTIALS).to_json()
        return f(*args, **kwargs)
    return decorated
class AuthError(Exception):
    def __init__(self, message, code=401):
        super().__init__(message)
        self.code = code
# def encode_auth_token(user_info,secret_key):
#     try:
#         payload = {
#             'exp': datetime.utcnow() + timedelta(hours=6),
#             'iat': datetime.utcnow(),
#             'user_account': user_info['account'],  # 使用 account 作为 sub
#             'user_id': user_info['id'],   # 添加 user_id 到 payload
#             'user_roles': user_info['roles']  # 添加 user_id 到 payload
#         }
#         return jwt.encode(payload,secret_key, algorithm='HS256')
#     except Exception as e:
#         return e
# def decode_auth_token(auth_token):
#     """解码认证令牌"""
#     try:
#         # 检查 SECRET_KEY 是否已设置
#         if not current_app.config.get('SECRET_KEY'):
#             raise AuthError('SECRET_KEY is not set', 500)
#         # 解码 JWT
#         payload = jwt.decode(auth_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
#         # 验证 JWT 的内容
#         if 'user_account' not in payload :
#             raise jwt.InvalidTokenError
#         if 'user_id' not in payload:
#             raise jwt.InvalidTokenError
#         # if 'user_account' not in payload:
#         #     raise jwt.InvalidTokenError
#         extracted_payload = {
#             'user_account': payload.get('user_account'),
#             'user_id': payload.get('user_id'),
#             'user_roles': payload.get('user_roles')
#         }
#
#         # 日志记录成功解码
#         current_app.logger.info("Token decoded successfully.")
#         return extracted_payload # 返回用户 ID 或其他标识符
#     except jwt.ExpiredSignatureError:
#         current_app.logger.warning("Token expired.")
#         raise AuthError('Token expired. Please log in again.', 401)
#     except jwt.InvalidTokenError as e:
#         current_app.logger.warning(f"Invalid token: {str(e)}")
#         raise AuthError('Invalid token. Please log in again.', 401)
#     except Exception as e:
#         current_app.logger.error(f"Unexpected error during token decoding: {str(e)}")
#         raise Unauthorized(description='An unexpected error occurred during token decoding.')
# class AuthError(Exception):
#     def __init__(self, message, code=401):
#         super().__init__(message)
#         self.code = code
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         if 'X-Token' in request.headers:
#             token = request.headers['X-Token']
#         if not token:
#             return R.error().set_message('Token is missing!').set_code(ResponseCode.TOKEN_EXPIRED).to_json()
#         try:
#             user_info = decode_auth_token(token)
#             g.current_user = user_info  # 将当前用户信息附加到全局变量g上
#         except Exception as e:
#             return R.error().set_message('Token is invalid!').set_code(ResponseCode.INVALID_CREDENTIALS).to_json()
#         return f(*args, **kwargs)
#     return decorated

