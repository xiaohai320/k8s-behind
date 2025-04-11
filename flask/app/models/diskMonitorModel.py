from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from zoneinfo import ZoneInfo
from app import db


class DiskMonitor(db.Model):
    __tablename__ = 'disk_monitor'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hostname = db.Column(db.String(255), nullable=False)  # 主机名
    disk_path = db.Column(db.String(255), nullable=False)  # 磁盘路径
    total_space = db.Column(db.String(255), nullable=False)  # 总空间（GB）
    used_space = db.Column(db.String(255), nullable=False)  # 已用空间（GB）
    free_space = db.Column(db.String(255), nullable=False)  # 可用空间（GB）
    percent_used = db.Column(db.Float, nullable=False)  # 使用百分比
    alert_threshold = db.Column(db.Float, nullable=False)  # 告警阈值
    # is_alert = db.Column(db.Boolean, nullable=False)  # 是否告警
    update_time = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Asia/Shanghai')),onupdate=datetime.now(ZoneInfo('Asia/Shanghai')))

    def to_dict(self):
        """将模型对象转换为字典"""
        return {
            "id": self.id,
            "hostname": self.hostname,
            "disk_path": self.disk_path,
            "total_space": self.total_space,
            "used_space": self.used_space,
            "free_space": self.free_space,
            "percent_used": self.percent_used,
            "alert_threshold": self.alert_threshold,
            # "is_alert": self.is_alert,
            "update_time": self.update_time.isoformat()
        }
