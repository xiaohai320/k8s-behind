from captcha.image import ImageCaptcha
from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from .extensions import init_redis_pool

from .config import Config  # 使用相对导入路径
# import redis

db = SQLAlchemy()
def create_app():
    app = Flask(__name__,
                static_url_path='/static',  # URL 前缀，默认为 '/static'
                static_folder='../static')
    app.config.from_object(Config)  # 直接使用 Config 类
    init_redis_pool(app)  # 初始化Redis连接池
    CORS(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()  # 创建所有表
    from .views.userinfoViews import user_bp
    from .views.captchaViews import captcha_bp  # 导入验证码蓝图
    app.register_blueprint(user_bp)
    app.register_blueprint(captcha_bp, url_prefix='/captcha')  # 注册验证码蓝图，并指定前缀
    return app