
from datetime import datetime
from zoneinfo import ZoneInfo

from app import db
class UserOperationLog(db.Model):
    __tablename__ = 'user_operations'
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    user_account = db.Column(db.String(64), nullable=False)  # 用户账号
    operation = db.Column(db.String(255), nullable=False)    # 操作描述
    timestamp = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))       # 操作时间
    details = db.Column(db.JSON, nullable=True)             # 操作详情，使用 JSON 字段存储
    def __repr__(self):
        return f"<UserOperationLog {self.id}>"

    def to_dict(self):
        """将模型实例转换为字典"""
        return {
            'id': self.id,
            'user_account': self.user_account,
            'operation': self.operation,
            'timestamp': self.timestamp.isoformat(),  # 将时间戳转换为 ISO 8601 格式的字符串
            'details': self.details
        }