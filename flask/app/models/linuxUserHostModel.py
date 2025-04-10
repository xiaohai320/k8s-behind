from datetime import datetime
from zoneinfo import ZoneInfo

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from app import db

class LinuxHost(db.Model):
    __tablename__ = 'linux_hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    description = db.Column(db.String(15), nullable=True)
    port = db.Column(db.Integer, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')))
    update_time = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')), onupdate=datetime.now(ZoneInfo('Asia/Shanghai')))
    users = relationship('LinuxUser', backref='host', lazy=True, cascade="all, delete-orphan")  # 确保 cascade 设置正确

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'create_time': self.create_time.isoformat(),
            'update_time': self.update_time.isoformat(),
            'users': [user.to_dict() for user in self.users],
            'description': self.description,
            'port': self.port
        }

class LinuxUser(db.Model):
    __tablename__ = 'linux_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('linux_hosts.id', ondelete='CASCADE'), nullable=False)


    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'host_id': self.host_id,
            'password': self.password
        }