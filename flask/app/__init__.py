import atexit

from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from .extensions import init_redis_pool
from kubernetes import client, config as k8sconfig
from .config import Config  # 使用相对导入路径
from apscheduler.schedulers.background import BackgroundScheduler



db = SQLAlchemy()

# 加载 Kubernetes 配置
k8sconfig.load_kube_config(config_file='flask\\app\\kubeconfig')
apps_v1 = client.AppsV1Api()
core_v1 = client.CoreV1Api()
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=False))
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
    from .views.kubeViews import k8s_bp
    from .views.kubeViews import alert_bp
    from .views.kubeViews import deploy_bp
    from .views.sshViews import ssh_bp
    from .views.processViews import process_monitor_bp
    from .views.diskViews import disk_monitor_bp
    from .views.echartsViews import prometheus_bp
    app.register_blueprint(prometheus_bp)
    app.register_blueprint(k8s_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(deploy_bp)
    app.register_blueprint(ssh_bp)
    app.register_blueprint(process_monitor_bp)
    app.register_blueprint(disk_monitor_bp)
    app.register_blueprint(captcha_bp, url_prefix='/captcha')  # 注册验证码蓝图，并指定前缀
    return app