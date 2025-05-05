# 装饰器：验证 Token
import json

from flask import request, jsonify, Blueprint, redirect, g
from flask_cors import CORS

from app.commonutils.R import R
from app.extensions import get_redis_client
from app.utils.auth import token_required

grafana_bp = Blueprint('grafana_bp', __name__)
CORS(grafana_bp, supports_credentials=True)

from urllib.parse import urlencode



@grafana_bp.route('/login/oauth/authorize', methods=['GET'])
def grafana_authorize():
    # 获取请求参数
    # client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    # 已登录，生成授权码
    code = "abcd"

    # 构造跳转 URL
    redirect_params = {
        'code': code,
        'state': state
    }
    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"

    # 重定向到目标 URL
    return redirect(redirect_url)
@grafana_bp.route('/grafanaLogin', methods=['GET'])
@token_required
def grafana_login():
    redis_client = get_redis_client()
    key = "user_grafana"
    value = {'account': g.current_user['user_account']}
    serialized_value = json.dumps(value)
    redis_client.setex(key, 3600, serialized_value)

    # 获取请求参数
    return R.ok().set_data("http://192.168.249.129:31091/login").to_json()


# 获取 Token 接口 (POST)
@grafana_bp.route('/login/oauth/token', methods=['POST'])
def grafana_token():
    code = request.form.get('code')
    if not code:
        return "Invalid code", 400
    return {'access_token': code, 'token_type': 'Bearer', 'expires_in': 3600}
# 获取用户信息接口 (GET)
@grafana_bp.route('/login/oauth/userinfo', methods=['GET'])
def userinfo():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 400
    redis_client = get_redis_client()
    stored_data = redis_client.get("user_grafana")
    stored_data = json.loads(stored_data)

    if redis_client.exists("user_grafana"):
        redis_client.delete("user_grafana")

    return jsonify({
        "sub": f"{stored_data['account']+"123"}",
        "name": f"{stored_data['account']}",
        "email": f"{stored_data['account']}@GuanXinTai.monitor"
    }), 200