import os
from pathlib import Path

# from dotenv import load_dotenv

# load_dotenv(Path('.env'))

class Config:
    """基本配置类"""
    SECRET_KEY = os.getenv('SECRET_KEY', '320320')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://root:320320@localhost/cluster_db')
    CAPTCHA_ENABLE= True
    CAPTCHA_LENGTH=4
    CAPTCHA_HEIGHT=60
    CAPTCHA_WIDTH=160
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = None  # 如果有密码，请设置