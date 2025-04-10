from datetime import datetime
from zoneinfo import ZoneInfo

from app import db
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship

class ScriptTask(db.Model):
    __tablename__ = 'script_tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(255),  nullable=False)
    last_runtime = db.Column(db.DateTime)
    last_executor = db.Column(db.String(255),  nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))
    updated_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'content': self.content,
            'author': self.author,
            'last_runtime': self.last_runtime.isoformat() if self.last_runtime else None,
            'last_executor': self.last_executor,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class ScriptLog(db.Model):
    """脚本执行日志模型"""
    __tablename__ = 'script_log'
    id = Column(Integer, primary_key=True)
    script_name = Column(db.String(255), nullable=False)
    host_info = Column(db.String(255), nullable=False)
    executor_role = Column(db.String(255), nullable=False)
    status = Column(db.String(255), nullable=False)
    result = Column(db.String(255), nullable=False)
    executor_at = Column(DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'script_name': self.script_name,
            'host_info': self.host_info,
            'executor_role': self.executor_role,
            'status': self.status,
            'result': self.result,
            'executor_at': self.executor_at.isoformat()
        }
