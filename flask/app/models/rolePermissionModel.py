from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import Text

from app import db


class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(64), unique=True, nullable=False)  # 角色名称
    permissions = db.Column(Text, nullable=False)            # 权限列表，逗号分隔
    created_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))       # 创建时间
    updated_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')), onupdate=datetime.now(ZoneInfo('Asia/Shanghai')))

    def to_dict(self):
        return {
            'id': self.id,
            'role_name': self.role_name,
            'permissions': self.permissions.split(',') if self.permissions else [],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
