# views/captchaViews.py
import secrets

from flask import Blueprint, request, jsonify, send_file
from io import BytesIO
from captcha.image import ImageCaptcha
import string
import random
from uuid import uuid4
from flask import current_app

from app.commonutils.R import R
from app.extensions import get_redis_client  # 使用全局连接池

captcha_bp = Blueprint('captcha_bp', __name__)

def generate_captcha_text():
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(chars) for _ in range(current_app.config['CAPTCHA_LENGTH']))

@captcha_bp.route('/get-captcha')
def get_captcha():
    image_captcha = ImageCaptcha(width=current_app.config['CAPTCHA_WIDTH'], height=current_app.config['CAPTCHA_HEIGHT'])
    captcha_text = generate_captcha_text()
    key = f"captcha:{uuid4()}"
    redis_client = get_redis_client()
    # 将验证码文本存入Redis，设置过期时间为3分钟
    redis_client.setex(key, 180, captcha_text)
    # 使用 captcha 库生成图像
    data = image_captcha.generate(captcha_text)
    # 返回包含验证码图片的数据流
    response = send_file(BytesIO(data.getvalue()), mimetype='image/png')
    response.headers['X-Captcha-Key'] = key  # 将key放在响应头中
    response.headers['Access-Control-Expose-Headers'] = 'X-Captcha-Key'
    return response
@captcha_bp.route('/verify-captcha', methods=['POST'])
def verify_captcha(user_input,key):
    print(key)
    redis_client = get_redis_client()
    stored_captcha = redis_client.get(key)
    if stored_captcha and stored_captcha.decode().lower() == user_input.lower():
        redis_client.delete(key)
        return True
    else:
        return False